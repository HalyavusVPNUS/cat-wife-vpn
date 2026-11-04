import base64
import html
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SOURCES = [
    {
        "name": "vless-converter",
        "url": "https://raw.githubusercontent.com/ReallySubHuman/vless-converter/refs/heads/main/vless.txt",
        "reject_russian_flag": True,
    },
    {
        "name": "Gidroksi",
        "url": "https://gidroksi.fun/free",
        "reject_russian_flag": False,
    },
]

OUTPUT_FILE = Path("cat.txt")
SING_BOX = os.environ.get("SING_BOX", "sing-box")

PER_SOURCE_LIMIT = 5
MAX_CANDIDATES_TO_TEST_PER_SOURCE = 60
WORKERS = 8                    # параллельных проверок
SOCKS_STARTUP_TIMEOUT = 8
PROBE_TIMEOUT = 10
MIN_SUCCESSES = 2              # сколько из PROBE_URLS должно ответить
MIN_TOTAL_TO_WRITE = 1         # минимум конфигов, чтобы перезаписать cat.txt

# Если 1 — когда ни один конфиг не прошёл реальную проверку, берём те,
# у которых хотя бы открывается TCP-порт сервера (может быть мусор!)
TCP_FALLBACK = os.environ.get("TCP_FALLBACK", "0") == "1"

HEADER = """#profile-title: Кошка жена ВПН 🐈
#profile-update-interval: 1
#subscription-userinfo: expire=86877705600; total=10995116277760; used=0
#profile-web-page-url: https://t.me/halyava_vpnx
#announce: 👲 Партия выдать тебе кошка жена + полный миска рис

"""

URI_RE = re.compile(r"""(?i)(?:vless|hysteria2|hy2)://[^\s<>"'`]+""")

USER_AGENTS = [
    "sing-box/1.14.4",
    "v2rayN/7.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
]

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/generate_204",
]

_port_lock = threading.Lock()
_used_ports = set()


# ---------------------------------------------------------------- fetching

def decode_base64_text(value):
    compact = re.sub(r"\s+", "", value)

    if len(compact) < 20:
        return None

    if not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return None

    try:
        padded = compact + "=" * (-len(compact) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = raw.decode("utf-8-sig")
        return decoded if "://" in decoded else None
    except Exception:
        return None


def extract_uris(body):
    text = html.unescape(body)
    text = text.replace("\\/", "/").strip()

    found = URI_RE.findall(text)

    if not found:
        decoded = decode_base64_text(text)
        if decoded:
            found = URI_RE.findall(html.unescape(decoded))

    if not found:
        fragments = re.findall(r"[A-Za-z0-9_+/=-]{80,}", text)
        for fragment in fragments:
            decoded = decode_base64_text(fragment)
            if decoded:
                found.extend(URI_RE.findall(decoded))

    cleaned = []
    seen = set()

    for item in found:
        item = item.rstrip(",;)]}，。")
        if item not in seen:
            seen.add(item)
            cleaned.append(item)

    return cleaned


def fetch_source(source):
    errors = []

    for user_agent in USER_AGENTS:
        request = urllib.request.Request(
            source["url"],
            headers={
                "User-Agent": user_agent,
                "Accept": "text/plain, */*",
                "Cache-Control": "no-cache",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=35) as response:
                body = response.read(12 * 1024 * 1024).decode(
                    "utf-8-sig", errors="replace"
                )

            uris = extract_uris(body)

            if uris:
                print(f"{source['name']}: extracted {len(uris)} links")
                return uris

            errors.append(f"{user_agent}: no supported links in response")

        except Exception as exc:
            errors.append(f"{user_agent}: {exc}")

    raise RuntimeError(
        f"{source['name']}: couldn't extract VLESS/Hysteria2 links. "
        "The URL may be an HTML/QR page instead of a raw subscription. "
        + " | ".join(errors)
    )


# ------------------------------------------------------- uri -> sing-box

def query_dict(parsed):
    values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {key: items[-1] for key, items in values.items() if items}


def truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def make_singbox_outbound(uri):
    parsed = urllib.parse.urlsplit(uri)
    scheme = parsed.scheme.lower()
    query = query_dict(parsed)

    try:
        server = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not server or not port:
        return None

    # ---------------- VLESS
    if scheme == "vless":
        user_id = urllib.parse.unquote(parsed.username or "")

        if not user_id:
            return None

        # новое vless-шифрование (mlkem и т.п.) sing-box не умеет
        encryption = query.get("encryption", "none").lower()
        if encryption not in {"none", ""}:
            return None

        outbound = {
            "type": "vless",
            "tag": "tested-proxy",
            "server": server,
            "server_port": port,
            "uuid": user_id,
        }

        flow = query.get("flow")
        if flow:
            outbound["flow"] = flow

        network = query.get("type", "tcp").lower()

        if network in {"ws", "httpupgrade"}:
            transport = {"type": network}

            path = query.get("path")
            host_header = query.get("host")

            if path:
                transport["path"] = urllib.parse.unquote(path)

            if host_header:
                transport["headers"] = {"Host": host_header}

            outbound["transport"] = transport

        elif network == "grpc":
            transport = {"type": "grpc"}

            service_name = query.get("serviceName") or query.get("service_name")
            if service_name:
                transport["service_name"] = service_name

            outbound["transport"] = transport

        elif network not in {"tcp", "raw", ""}:
            return None

        security = query.get("security", "none").lower()

        if security in {"tls", "reality"}:
            tls = {
                "enabled": True,
                "server_name": (
                    query.get("sni") or query.get("serverName") or server
                ),
            }

            if truthy(query.get("allowInsecure", "")) or truthy(
                query.get("insecure", "")
            ):
                tls["insecure"] = True

            alpn = query.get("alpn")
            if alpn:
                tls["alpn"] = [
                    v for v in urllib.parse.unquote(alpn).split(",") if v
                ]

            fingerprint = query.get("fp") or query.get("fingerprint")
            if fingerprint:
                tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

            if security == "reality":
                public_key = query.get("pbk") or query.get("publicKey")

                if not public_key:
                    return None

                reality = {"enabled": True, "public_key": public_key}

                short_id = query.get("sid") or query.get("shortId")
                if short_id:
                    reality["short_id"] = short_id

                tls["reality"] = reality

                # reality без utls не работает — ставим по умолчанию
                if "utls" not in tls:
                    tls["utls"] = {"enabled": True, "fingerprint": "chrome"}

            outbound["tls"] = tls

        elif security not in {"none", ""}:
            return None

        return outbound

    # ---------------- Hysteria2
    if scheme in {"hy2", "hysteria2"}:
        username = urllib.parse.unquote(parsed.username or "")
        password_part = urllib.parse.unquote(parsed.password or "")

        auth = f"{username}:{password_part}" if password_part else username

        if not auth:
            return None

        tls = {
            "enabled": True,
            "server_name": query.get("sni") or server,
        }

        if truthy(query.get("insecure", "")):
            tls["insecure"] = True

        alpn = query.get("alpn")
        if alpn:
            tls["alpn"] = [v for v in alpn.split(",") if v]

        outbound = {
            "type": "hysteria2",
            "tag": "tested-proxy",
            "server": server,
            "server_port": port,
            "password": auth,
            "tls": tls,
        }

        obfs_type = query.get("obfs", "").lower()
        obfs_password = query.get("obfs-password") or query.get("obfs_password")

        if obfs_type:
            if obfs_type != "salamander" or not obfs_password:
                return None

            outbound["obfs"] = {"type": "salamander", "password": obfs_password}

        return outbound

    return None


# ------------------------------------------------------------- probing

def free_local_port():
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]

        with _port_lock:
            if port not in _used_ports:
                _used_ports.add(port)
                return port


def wait_for_port(process, port):
    deadline = time.monotonic() + SOCKS_STARTUP_TIMEOUT

    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)

    return False


def build_config(outbound, port, modern):
    config = {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "local-socks",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        ],
        "outbounds": [outbound],
        "route": {"final": "tested-proxy"},
    }

    if modern:
        # sing-box 1.12+: нужен резолвер для доменных адресов серверов
        config["dns"] = {
            "servers": [
                {"type": "udp", "tag": "dns-direct", "server": "8.8.8.8"}
            ]
        }
        config["route"]["default_domain_resolver"] = "dns-direct"

    return config


def tail(text, limit=200):
    text = (text or "").strip().replace("\n", " | ")
    return text[-limit:]


def probe_through_singbox(outbound):
    """Возвращает (latency | None, причина)."""
    port = free_local_port()

    try:
        with tempfile.TemporaryDirectory(prefix="cat-vpn-check-") as tmp:
            config_path = None
            check_err = ""

            for modern in (True, False):
                candidate_path = Path(tmp) / f"config_{int(modern)}.json"
                candidate_path.write_text(
                    json.dumps(build_config(outbound, port, modern)),
                    encoding="utf-8",
                )

                checked = subprocess.run(
                    [SING_BOX, "check", "-c", str(candidate_path)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if checked.returncode == 0:
                    config_path = candidate_path
                    break

                check_err = tail(checked.stderr or checked.stdout)

            if config_path is None:
                return None, f"config rejected: {check_err}"

            log_path = Path(tmp) / "sing-box.log"

            with open(log_path, "wb") as log_file:
                process = subprocess.Popen(
                    [SING_BOX, "run", "-c", str(config_path)],
                    stdout=log_file,
                    stderr=log_file,
                )

                try:
                    if not wait_for_port(process, port):
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        log = log_path.read_text(errors="replace")
                        return None, f"sing-box didn't start: {tail(log)}"

                    successes = 0
                    latencies = []
                    last_error = ""

                    for url in PROBE_URLS:
                        started = time.monotonic()

                        try:
                            result = subprocess.run(
                                [
                                    "curl",
                                    "--silent",
                                    "--show-error",
                                    "--location",
                                    "--connect-timeout", "6",
                                    "--max-time", str(PROBE_TIMEOUT),
                                    "--proxy", f"socks5h://127.0.0.1:{port}",
                                    "--output", "/dev/null",
                                    "--write-out", "%{http_code}",
                                    url,
                                ],
                                capture_output=True,
                                text=True,
                                timeout=PROBE_TIMEOUT + 3,
                            )

                            status = result.stdout.strip()

                            if result.returncode == 0 and status.startswith("2"):
                                successes += 1
                                latencies.append(time.monotonic() - started)
                            else:
                                last_error = (
                                    f"curl rc={result.returncode} "
                                    f"http={status} {tail(result.stderr, 80)}"
                                )

                        except (subprocess.TimeoutExpired, OSError) as exc:
                            last_error = f"probe error: {exc}"

                        if successes >= MIN_SUCCESSES:
                            break

                    if successes >= MIN_SUCCESSES:
                        return sum(latencies) / len(latencies), "ok"

                    log = log_path.read_text(errors="replace")
                    return None, f"{last_error} | sing-box: {tail(log, 120)}"

                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=2)

    except Exception as exc:
        return None, f"exception: {exc}"

    finally:
        with _port_lock:
            _used_ports.discard(port)


def tcp_reachable(outbound):
    try:
        with socket.create_connection(
            (outbound["server"], outbound["server_port"]), timeout=4
        ):
            return True
    except OSError:
        return False


# ---------------------------------------------------------- selection

def get_working(source):
    candidates = fetch_source(source)

    if source["reject_russian_flag"]:
        candidates = [
            item
            for item in candidates
            if "🇷🇺" not in urllib.parse.unquote(html.unescape(item))
        ]

    jobs = []
    seen = set()

    for uri in candidates:
        if uri in seen:
            continue
        seen.add(uri)

        outbound = make_singbox_outbound(uri)
        if outbound is None:
            continue

        jobs.append((uri, outbound))

        if len(jobs) >= MAX_CANDIDATES_TO_TEST_PER_SOURCE:
            break

    print(f"{source['name']}: {len(jobs)} candidates to test")

    passed = []
    failed_outbounds = []
    enough = threading.Event()
    stop_after = PER_SOURCE_LIMIT * 2  # запас, чтобы выбрать самые быстрые

    def work(index, uri, outbound):
        if enough.is_set():
            return index, uri, outbound, None, "skipped (enough found)"
        latency, reason = probe_through_singbox(outbound)
        return index, uri, outbound, latency, reason

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [
            pool.submit(work, i, uri, outbound)
            for i, (uri, outbound) in enumerate(jobs, 1)
        ]

        for future in as_completed(futures):
            index, uri, outbound, latency, reason = future.result()

            if reason.startswith("skipped"):
                continue

            if latency is not None:
                print(f"{source['name']} #{index}: PASS ({latency:.2f}s)")
                passed.append((latency, uri))
                if len(passed) >= stop_after:
                    enough.set()
            else:
                print(f"{source['name']} #{index}: FAIL - {reason}")
                failed_outbounds.append((uri, outbound))

    passed.sort(key=lambda item: item[0])
    selected = [uri for _, uri in passed[:PER_SOURCE_LIMIT]]

    if not selected and TCP_FALLBACK:
        print(f"{source['name']}: TCP fallback enabled")
        for uri, outbound in failed_outbounds:
            if tcp_reachable(outbound):
                selected.append(uri)
            if len(selected) >= PER_SOURCE_LIMIT:
                break

    if len(selected) < PER_SOURCE_LIMIT:
        print(
            f"WARNING: {source['name']}: only {len(selected)} configs passed "
            f"(wanted {PER_SOURCE_LIMIT})"
        )

    print(f"{source['name']}: selected {len(selected)} configs")
    return selected


def main():
    all_configs = []

    for source in SOURCES:
        try:
            all_configs.extend(get_working(source))
        except Exception as exc:
            print(f"ERROR in source {source['name']}: {exc}")

    if len(all_configs) < MIN_TOTAL_TO_WRITE:
        print("No working configs found; keeping existing cat.txt")
        sys.exit(1)

    content = HEADER + "\n".join(all_configs) + "\n"
    OUTPUT_FILE.write_text(content, encoding="utf-8")

    print(f"Done: wrote {len(all_configs)} configs to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
