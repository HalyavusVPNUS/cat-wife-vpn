
import base64
import html
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

SOURCES = [
    {
        "name": "AeryxVPN",
        "url": "https://aeryxvpn-sub.aeryxvpn.workers.dev",
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
MAX_CANDIDATES_TO_TEST_PER_SOURCE = 35
SOCKS_STARTUP_TIMEOUT = 5
PROBE_TIMEOUT = 7

HEADER = """#profile-title: Кошка жена ВПН 🐈
#profile-update-interval: 1
#subscription-userinfo: expire=86877705600; total=10995116277760; used=0
#profile-web-page-url: https://t.me/halyava_vpnx
#announce: 👲 Партия выдать тебе кошка жена + полный миска рис

"""

URI_RE = re.compile(
    r"""(?i)(?:vless|hysteria2|hy2)://[^\s<>"'`]+"""
)

USER_AGENTS = [
    "sing-box/1.14.4",
    "v2rayN/7.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
]

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]


def decode_base64_text(value):
    compact = re.sub(r"\s+", "", value)

    if len(compact) < 20:
        return None

    if not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return None

    try:
        padded = compact + "=" * (-len(compact) % 4)
        raw = base64.urlsafe_b64decode(
            padded.encode("ascii")
        )
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
        fragments = re.findall(
            r"[A-Za-z0-9_+/=-]{80,}", text
        )

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
            with urllib.request.urlopen(
                request, timeout=35
            ) as response:
                body = response.read(
                    12 * 1024 * 1024
                ).decode(
                    "utf-8-sig",
                    errors="replace"
                )

            uris = extract_uris(body)

            if uris:
                print(
                    f"{source['name']}: extracted {len(uris)} links"
                )
                return uris

            errors.append("No supported links")

        except Exception as exc:
            errors.append(str(exc))

    raise RuntimeError(
        f"{source['name']}: download failed: "
        + " | ".join(errors)
    )


def query_dict(parsed):
    values = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    return {
        key: items[-1]
        for key, items in values.items()
        if items
    }


def truthy(value):
    return str(value).strip().lower() in {
        "1", "true", "yes", "on"
    }


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

    if scheme == "vless":
        user_id = urllib.parse.unquote(
            parsed.username or ""
        )

        if not user_id:
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

        if network == "ws":
            transport = {"type": "ws"}

            path = query.get("path")
            host = query.get("host")

            if path:
                transport["path"] = path

            if host:
                transport["headers"] = {"Host": host}

            outbound["transport"] = transport

        elif network == "grpc":
            transport = {"type": "grpc"}

            service = (
                query.get("serviceName")
                or query.get("service_name")
            )

            if service:
                transport["service_name"] = service

            outbound["transport"] = transport

        elif network == "httpupgrade":
            transport = {"type": "httpupgrade"}

            path = query.get("path")
            host = query.get("host")

            if path:
                transport["path"] = path

            if host:
                transport["headers"] = {"Host": host}

            outbound["transport"] = transport

        elif network not in {"tcp", "raw", ""}:
            return None

        security = query.get(
            "security", "none"
        ).lower()

        if security in {"tls", "reality"}:
            tls = {
                "enabled": True,
                "server_name": (
                    query.get("sni")
                    or query.get("serverName")
                    or server
                ),
            }

            if truthy(query.get("allowInsecure", "")):
                tls["insecure"] = True

            fingerprint = (
                query.get("fp")
                or query.get("fingerprint")
            )

            if fingerprint:
                tls["utls"] = {
                    "enabled": True,
                    "fingerprint": fingerprint,
                }

            if security == "reality":
                public_key = (
                    query.get("pbk")
                    or query.get("publicKey")
                )

                if not public_key:
                    return None

                reality = {
                    "enabled": True,
                    "public_key": public_key,
                }

                short_id = (
                    query.get("sid")
                    or query.get("shortId")
                )

                if short_id:
                    reality["short_id"] = short_id

                tls["reality"] = reality

            outbound["tls"] = tls

        elif security not in {"none", ""}:
            return None

        return outbound

    if scheme in {"hy2", "hysteria2"}:
        username = urllib.parse.unquote(
            parsed.username or ""
        )

        password_part = urllib.parse.unquote(
            parsed.password or ""
        )

        auth = (
            f"{username}:{password_part}"
            if password_part
            else username
        )

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
            tls["alpn"] = [
                value for value in alpn.split(",")
                if value
            ]

        outbound = {
            "type": "hysteria2",
            "tag": "tested-proxy",
            "server": server,
            "server_port": port,
            "password": auth,
            "tls": tls,
        }

        obfs_type = query.get("obfs", "").lower()

        obfs_password = (
            query.get("obfs-password")
            or query.get("obfs_password")
        )

        if obfs_type:
            if (
                obfs_type != "salamander"
                or not obfs_password
            ):
                return None

            outbound["obfs"] = {
                "type": "salamander",
                "password": obfs_password,
            }

        return outbound

    return None


def free_local_port():
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(process, port):
    deadline = time.monotonic() + SOCKS_STARTUP_TIMEOUT

    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False

        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.25
            ):
                return True
        except OSError:
            time.sleep(0.1)

    return False


def probe_through_singbox(outbound):
    port = free_local_port()

    config = {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "local-socks",
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [outbound],
        "route": {"final": "tested-proxy"},
    }

    with tempfile.TemporaryDirectory(
        prefix="cat-vpn-check-"
    ) as tmp:

        config_path = Path(tmp) / "config.json"

        config_path.write_text(
            json.dumps(config),
            encoding="utf-8"
        )

        checked = subprocess.run(
            [
                SING_BOX,
                "check",
                "-c",
                str(config_path)
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if checked.returncode != 0:
            print("  Invalid sing-box config")
            return None

        process = subprocess.Popen(
            [
                SING_BOX,
                "run",
                "-c",
                str(config_path)
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            if not wait_for_port(process, port):
                return None

            successes = 0
            latencies = []

            for url in PROBE_URLS:
                started = time.monotonic()

                try:
                    result = subprocess.run(
                        [
                            "curl",
                            "--silent",
                            "--show-error",
                            "--location",
                            "--connect-timeout",
                            "4",
                            "--max-time",
                            str(PROBE_TIMEOUT),
                            "--proxy",
                            f"socks5h://127.0.0.1:{port}",
                            "--output",
                            "/dev/null",
                            "--write-out",
                            "%{http_code}",
                            url,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=PROBE_TIMEOUT + 2,
                    )

                    status = result.stdout.strip()

                    if (
                        result.returncode == 0
                        and status.startswith("2")
                    ):
                        successes += 1
                        latencies.append(
                            time.monotonic() - started
                        )

                except (
                    subprocess.TimeoutExpired,
                    OSError
                ):
                    pass

            if successes >= 3:
                return sum(latencies) / len(latencies)

            return None

        finally:
            process.terminate()

            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def get_five_working(source):
    candidates = fetch_source(source)

    if source["reject_russian_flag"]:
        candidates = [
            item for item in candidates
            if "🇷🇺" not in urllib.parse.unquote(
                html.unescape(item)
            )
        ]

    passed = []
    seen = set()
    tested = 0

    for uri in candidates:
        if uri in seen:
            continue

        seen.add(uri)

        outbound = make_singbox_outbound(uri)

        if outbound is None:
            continue

        if tested >= MAX_CANDIDATES_TO_TEST_PER_SOURCE:
            break

        tested += 1

        print(
            f"{source['name']}: testing "
            f"{tested}/{MAX_CANDIDATES_TO_TEST_PER_SOURCE}"
        )

        latency = probe_through_singbox(outbound)

        if latency is not None:
            print(f"  PASS: {latency:.2f}s")
            passed.append((latency, uri))
        else:
            print("  FAIL")

    passed.sort(key=lambda item: item[0])

    selected = [
        uri for _, uri in passed[:PER_SOURCE_LIMIT]
    ]

    if len(selected) < PER_SOURCE_LIMIT:
        raise RuntimeError(
            f"{source['name']}: only {len(selected)} "
            f"configs passed. Need 5. "
            "Old cat.txt preserved."
        )

    print(
        f"{source['name']}: selected {len(selected)}"
    )

    return selected


def main():
    all_configs = []

    for source in SOURCES:
        selected = get_five_working(source)
        all_configs.extend(selected)

    if len(all_configs) != 10:
        raise RuntimeError(
            "Expected exactly 10 configs. "
            "Old cat.txt preserved."
        )

    content = HEADER + "\n".join(all_configs) + "\n"

    OUTPUT_FILE.write_text(
        content,
        encoding="utf-8"
    )

    print(
        f"SUCCESS: saved {len(all_configs)} configs"
    )


if __name__ == "__main__":
    main()
