import base64
import html
import json
import math
import os
import random
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
        "name": "fixnet",
        "title": "Кошка жена ВПН 🐈",
        "url": "https://raw.githubusercontent.com/HalyavusVPNUS/cat-wife-vpn/refs/heads/main/Fixnet.gg",
        "reject_russian_flag": False,
        # xhttp-конфиги sing-box проверить не может, поэтому берём их без проверки
        # (при открытом TCP-порте). Выбор рабочего делает balancer в Happ.
        "fill_unverified": True,
        "limit": 10,                # конфигов в JSON
        # только Латвия и Швеция (по флагу или названию страны в имени конфига)
        "allowed_countries": [
            "🇱🇻", "latvia", "латвия", "латвии",
            "🇸🇪", "sweden", "швеция", "швеции",
        ],
    },
    {
        "name": "okeania",
        "title": "Okeania 🌊",
        "url": "https://raw.githubusercontent.com/HalyavusVPNUS/vless-subscription/refs/heads/main/hysteria.txt",
        "reject_russian_flag": False,
        "allow_hysteria": True,
        # В файле лежат vless-конфиги (в т.ч. «белые списки» и xhttp), которые
        # с раннера GitHub не проходят проверку. Без добора JSON получался пустым
        # и пропускался, поэтому добираем непроверенными (при открытом TCP-порте).
        "fill_unverified": True,
        "limit": 5,                 # конфигов в JSON
        # allowed_countries нет: берём все страны
    },
]

OUTPUT_FILE = Path("cat.txt")
SING_BOX = os.environ.get("SING_BOX", "sing-box")

# True  = в JSON идут все стабильные конфиги, без лимита.
# False = лимит источника ("limit"), берутся самые стабильные.
UNLIMITED = False
# В режиме UNLIMITED: добавлять ли конфиги, которые sing-box проверить не может (xhttp и т.п.)
INCLUDE_UNTESTABLE = False

PER_SOURCE_LIMIT = 10          # если у источника нет своего "limit"
# сколько кандидатов тестировать на источник (None = все)
MAX_CANDIDATES_TO_TEST_PER_SOURCE = None
SOURCE_TIME_BUDGET = 1500                 # сек на один источник (защита от долгого job)
WORKERS = 8                    # параллельных проверок
SOCKS_STARTUP_TIMEOUT = 8
PROBE_TIMEOUT = 10
MIN_SUCCESSES = 1              # первичная проверка: хотя бы один ответ через прокси
MIN_TOTAL_TO_WRITE = 1         # минимум профилей, чтобы перезаписать cat.txt

# --- Проверка стабильности ------------------------------------------------
# Конфиг не просто «ответил раз», а несколько раундов подряд с паузами,
# и по HTTP, и по HTTPS (HTTPS ловит конфиги, где туннель живой, но TLS через него рвётся).
STABILITY_ROUNDS = 6           # раундов проверки
STABILITY_PAUSE = 1.5          # пауза между раундами, сек
MIN_STABILITY = 0.75           # доля успешных запросов, ниже которой конфиг отбрасывается
STABILITY_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
]

# --- JSON-режим для Happ -------------------------------------------------
# cat.txt = ЧИСТЫЙ JSON (без #-заголовков, иначе Happ пишет "no server link").
# Название подписки отдаётся HTTP-заголовком через worker.js.
BALANCER_PROBE_URL = "https://www.gstatic.com/generate_204"
BALANCER_PROBE_INTERVAL = "1m"
PROFILE_TITLE = "Кошка жена ВПН 🐈"   # запасное название, если у источника нет "title"

# Откуда считаем «близко»: где живёт аудитория подписки (по умолчанию Москва).
# Пинг с раннера GitHub (США) для пользователей не показателен, поэтому
# при равной стабильности конфиги ранжируются по расстоянию до этой точки.
REFERENCE_LOCATION = (
    float(os.environ.get("REF_LAT", "55.75")),
    float(os.environ.get("REF_LON", "37.62")),
)
GEO_BUCKET_MS = 25   # конфиги в пределах 25 мс считаем равными, дальше решает замер

URI_RE = re.compile(r"""(?i)(?:vless|hysteria2|hy2)://[^\s<>"'`]+""")
# построчный разбор: строка целиком, включая кавычки внутри (JSON в параметре extra)
LINE_URI_RE = re.compile(r"(?im)^\s*((?:vless|hysteria2|hy2)://\S+)\s*$")

USER_AGENTS = [
    "sing-box/1.14.4",
    "v2rayN/7.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
]

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/generate_204",
    "https://ya.ru",          # на случай серверов «белых списков»
]


def ok_status(code):
    """Любой нормальный HTTP-ответ через прокси = туннель работает."""
    code = str(code).strip()
    return code.isdigit() and 200 <= int(code) < 500

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


def dedupe_list(items):
    cleaned = []
    seen = set()

    for item in items:
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)

    return cleaned


def extract_line_uris(text):
    """Ссылки по одной на строку: берём строку целиком (кавычки внутри допустимы)."""
    return dedupe_list(
        match.rstrip(",;") for match in LINE_URI_RE.findall(text)
    )


def extract_regex_uris(text):
    """Запасной вариант: ссылки внутри HTML/JSON, где кавычка = конец ссылки."""
    return dedupe_list(
        item.rstrip(",;)]}，。") for item in URI_RE.findall(text)
    )


def extract_uris(body):
    text = html.unescape(body)
    text = text.replace("\\/", "/").strip()

    found = extract_line_uris(text)

    if not found:
        found = extract_regex_uris(text)

    if not found:
        decoded = decode_base64_text(text)
        if decoded:
            decoded = html.unescape(decoded)
            found = extract_line_uris(decoded) or extract_regex_uris(decoded)

    if not found:
        fragments = re.findall(r"[A-Za-z0-9_+/=-]{80,}", text)
        for fragment in fragments:
            decoded = decode_base64_text(fragment)
            if decoded:
                found.extend(
                    extract_line_uris(decoded) or extract_regex_uris(decoded)
                )

    return dedupe_list(found)


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


# ------------------------------------------------------- uri -> xray json

def make_xray_hysteria_outbound(parsed, query, tag):
    """hy2:// -> outbound xray (protocol hysteria, version 2).
    Нужен свежий xray-core; в старых версиях Happ такой конфиг не заведётся."""
    try:
        server = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    username = urllib.parse.unquote(parsed.username or "")
    password_part = urllib.parse.unquote(parsed.password or "")
    auth = f"{username}:{password_part}" if password_part else username

    if not server or not port or not auth:
        return None

    tls = {"serverName": query.get("sni") or server}

    if truthy(query.get("insecure", "")) or truthy(query.get("allowInsecure", "")):
        tls["allowInsecure"] = True

    alpn = query.get("alpn")
    tls["alpn"] = [v for v in urllib.parse.unquote(alpn).split(",") if v] if alpn else ["h3"]

    stream = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": {"version": 2, "auth": auth},
    }

    obfs_type = query.get("obfs", "").lower()
    obfs_password = query.get("obfs-password") or query.get("obfs_password")

    if obfs_type:
        if obfs_type != "salamander" or not obfs_password:
            return None
        stream["finalmask"] = {
            "udp": [{"type": "salamander", "settings": {"password": obfs_password}}]
        }

    return {
        "tag": tag,
        "protocol": "hysteria",
        "settings": {"version": 2, "address": server, "port": port},
        "streamSettings": stream,
    }


def make_xray_outbound(uri, tag, allow_hysteria=False):
    """vless:// (и hy2://, если разрешено) -> outbound в формате xray."""
    parsed = urllib.parse.urlsplit(uri)
    scheme = parsed.scheme.lower()

    if scheme in {"hy2", "hysteria2"}:
        if not allow_hysteria:
            return None
        return make_xray_hysteria_outbound(parsed, query_dict(parsed), tag)

    if scheme != "vless":
        return None

    query = query_dict(parsed)

    try:
        server = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    user_id = urllib.parse.unquote(parsed.username or "")

    if not server or not port or not user_id:
        return None

    user = {
        "id": user_id,
        "encryption": query.get("encryption") or "none",
    }

    flow = query.get("flow")
    if flow:
        user["flow"] = flow

    network = (query.get("type") or "tcp").lower()
    if network in {"raw", ""}:
        network = "tcp"

    stream = {"network": network}

    path = urllib.parse.unquote(query.get("path", ""))
    host_header = query.get("host", "")

    if network == "ws":
        ws = {}
        if path:
            ws["path"] = path
        if host_header:
            ws["headers"] = {"Host": host_header}
        stream["wsSettings"] = ws

    elif network == "httpupgrade":
        hu = {}
        if path:
            hu["path"] = path
        if host_header:
            hu["host"] = host_header
        stream["httpupgradeSettings"] = hu

    elif network == "grpc":
        grpc = {}
        service_name = query.get("serviceName") or query.get("service_name")
        if service_name:
            grpc["serviceName"] = service_name
        if truthy(query.get("multiMode", "")) or query.get("mode") == "multi":
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc

    elif network in {"xhttp", "splithttp"}:
        stream["network"] = "xhttp"
        xh = {}
        if path:
            xh["path"] = path
        if host_header:
            xh["host"] = host_header
        if query.get("mode"):
            xh["mode"] = query["mode"]
        extra = query.get("extra")
        if extra:
            try:
                xh["extra"] = json.loads(urllib.parse.unquote(extra))
            except ValueError:
                pass
        stream["xhttpSettings"] = xh

    elif network == "tcp":
        if (query.get("headerType") or "").lower() == "http":
            request = {"path": [path or "/"]}
            if host_header:
                request["headers"] = {"Host": host_header.split(",")}
            stream["tcpSettings"] = {
                "header": {"type": "http", "request": request}
            }

    else:
        return None

    security = (query.get("security") or "none").lower()
    fingerprint = query.get("fp") or query.get("fingerprint")
    sni = query.get("sni") or query.get("serverName") or server

    if security == "tls":
        tls = {"serverName": sni}

        if truthy(query.get("allowInsecure", "")) or truthy(
            query.get("insecure", "")
        ):
            tls["allowInsecure"] = True

        alpn = query.get("alpn")
        if alpn:
            tls["alpn"] = [
                v for v in urllib.parse.unquote(alpn).split(",") if v
            ]

        if fingerprint:
            tls["fingerprint"] = fingerprint

        stream["security"] = "tls"
        stream["tlsSettings"] = tls

    elif security == "reality":
        public_key = query.get("pbk") or query.get("publicKey")

        if not public_key:
            return None

        reality = {
            "serverName": sni,
            "fingerprint": fingerprint or "chrome",
            "publicKey": public_key,
            "shortId": query.get("sid") or query.get("shortId") or "",
            "spiderX": urllib.parse.unquote(query.get("spx", "")),
        }

        stream["security"] = "reality"
        stream["realitySettings"] = reality

    elif security in {"none", ""}:
        stream["security"] = "none"

    else:
        return None

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": server, "port": port, "users": [user]}]
        },
        "streamSettings": stream,
    }


def build_happ_json(source_name, uris, allow_hysteria=False, title=None):
    """Один xray-JSON: все конфиги + автовыбор по пингу."""
    proxies = []

    for uri in uris:
        outbound = make_xray_outbound(
            uri, f"proxy-{len(proxies) + 1}", allow_hysteria
        )
        if outbound is not None:
            proxies.append(outbound)

    if not proxies:
        return None

    config = {
        "remarks": title or PROFILE_TITLE,
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIP"},
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
        ],
        "outbounds": proxies
        + [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "observatory": {
            "subjectSelector": ["proxy-"],
            "probeUrl": BALANCER_PROBE_URL,
            "probeInterval": BALANCER_PROBE_INTERVAL,
            "enableConcurrency": True,
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {
                    "tag": "auto",
                    "selector": ["proxy-"],
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": "proxy-1",
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "auto",
                }
            ],
        },
    }

    return config


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


def measure_stability(port):
    """Несколько раундов с паузами, HTTP + HTTPS.
    Возвращает (доля успешных запросов, медианная задержка | None).
    Выходит раньше, если стабильность уже не набрать."""
    total = STABILITY_ROUNDS * len(STABILITY_URLS)
    max_failures = int(total * (1 - MIN_STABILITY))
    failures = 0
    samples = []

    for round_index in range(STABILITY_ROUNDS):
        if round_index:
            time.sleep(STABILITY_PAUSE)

        for url in STABILITY_URLS:
            try:
                result = subprocess.run(
                    [
                        "curl",
                        "--silent",
                        "--connect-timeout", "5",
                        "--max-time", "8",
                        "--proxy", f"socks5h://127.0.0.1:{port}",
                        "--output", "/dev/null",
                        "--write-out", "%{http_code}|%{time_total}",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=11,
                )

                code, _, elapsed = result.stdout.strip().partition("|")

                if result.returncode == 0 and ok_status(code):
                    samples.append(float(elapsed))
                    continue

            except (subprocess.TimeoutExpired, OSError, ValueError):
                pass

            failures += 1

            if failures > max_failures:
                return (total - failures) / total, None

    ratio = len(samples) / total

    if not samples:
        return 0.0, None

    samples.sort()
    return ratio, samples[len(samples) // 2]


def probe_through_singbox(outbound):
    """Возвращает ((latency, stability) | None, причина)."""
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
                    last_error = ""

                    for url in PROBE_URLS:
                        try:
                            result = subprocess.run(
                                [
                                    "curl",
                                    "--silent",
                                    "--show-error",
                                    "--location",
                                    "--connect-timeout", "10",
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

                            if result.returncode == 0 and ok_status(status):
                                successes += 1
                            else:
                                last_error = (
                                    f"curl rc={result.returncode} "
                                    f"http={status} {tail(result.stderr, 80)}"
                                )

                        except (subprocess.TimeoutExpired, OSError) as exc:
                            last_error = f"probe error: {exc}"

                        if successes >= MIN_SUCCESSES:
                            break

                    if successes < MIN_SUCCESSES:
                        log = log_path.read_text(errors="replace")
                        return None, f"{last_error} | sing-box: {tail(log, 300)}"

                    # туннель ответил: теперь проверяем, насколько он стабилен
                    ratio, latency = measure_stability(port)

                    if latency is None or ratio < MIN_STABILITY:
                        return None, f"unstable: {ratio:.0%} of requests ok"

                    return (latency, ratio), "ok"

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


# ---------------------------------------------------------- geo ranking

def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def geolocate(hosts):
    """host -> (lat, lon, country). Бесплатный ip-api.com, пачками по 100."""
    resolved = {}

    for host in hosts:
        if not host:
            continue
        try:
            resolved[host] = socket.gethostbyname(host)
        except OSError:
            pass

    ips = sorted(set(resolved.values()))
    by_ip = {}

    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            request = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,query,countryCode,lat,lon",
                data=json.dumps([{"query": ip} for ip in chunk]).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                for row in json.loads(response.read().decode()):
                    if row.get("status") == "success":
                        by_ip[row["query"]] = (
                            row["lat"], row["lon"], row.get("countryCode", "??")
                        )
        except Exception as exc:
            print(f"  geolocation failed: {exc}")

    return {
        host: by_ip[ip] for host, ip in resolved.items() if ip in by_ip
    }


def estimate_ping_ms(host, geo):
    """Примерный пинг от аудитории до сервера по расстоянию. (мс, страна)."""
    info = geo.get(host)

    if not info:
        return 150.0, "??"   # неизвестно: считаем средним

    km = haversine_km(REFERENCE_LOCATION[0], REFERENCE_LOCATION[1], info[0], info[1])
    return 10 + km / 60, info[2]


def geo_bucket(uri, geo):
    host, _ = uri_endpoint(uri)
    est, _ = estimate_ping_ms(host, geo)
    return round(est / GEO_BUCKET_MS)


# ---------------------------------------------------------- selection

def matches_country(uri, markers):
    """Проверяет только название конфига (часть после #), не всю ссылку."""
    fragment = urllib.parse.unquote(
        html.unescape(urllib.parse.urlsplit(uri).fragment)
    ).lower()

    return any(marker.lower() in fragment for marker in markers)


def tcp_rtt(host, port):
    """Время TCP-подключения к серверу в секундах (None = порт закрыт)."""
    if not host or not port:
        return None
    if host.startswith("127.") or host in {"localhost", "0.0.0.0"}:
        return None

    started = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=5):
            return time.monotonic() - started
    except OSError:
        return None


def tcp_open(host, port):
    return tcp_rtt(host, port) is not None


def dedupe_key(uri):
    """Один и тот же сервер с разными fp= считаем одним конфигом."""
    try:
        parsed = urllib.parse.urlsplit(uri)
        query = query_dict(parsed)
        return (
            parsed.scheme.lower(),
            parsed.username,
            (parsed.hostname or "").lower(),
            parsed.port,
            query.get("type", "tcp"),
            query.get("security", ""),
            query.get("sni", ""),
            query.get("pbk", ""),
            query.get("path", ""),
            query.get("serviceName", ""),
            query.get("flow", ""),
        )
    except ValueError:
        return uri


def uri_endpoint(uri):
    try:
        parsed = urllib.parse.urlsplit(uri)
        return parsed.hostname, parsed.port
    except ValueError:
        return None, None


def get_working(source):
    # None = без ограничений
    if UNLIMITED:
        limit = None
    else:
        limit = source.get("limit", PER_SOURCE_LIMIT)

    allow_hysteria = source.get("allow_hysteria", False)

    candidates = fetch_source(source)

    # источники без поддержки hysteria: выкидываем hy2 сразу,
    # чтобы они не занимали места в выборке
    if not allow_hysteria:
        candidates = [
            item for item in candidates if item.lower().startswith("vless://")
        ]

    if source["reject_russian_flag"]:
        candidates = [
            item
            for item in candidates
            if "\U0001F1F7\U0001F1FA" not in urllib.parse.unquote(html.unescape(item))
        ]

    allowed = source.get("allowed_countries")

    if allowed:
        before = len(candidates)
        candidates = [
            item for item in candidates if matches_country(item, allowed)
        ]
        print(
            f"{source['name']}: country filter kept "
            f"{len(candidates)} of {before} links"
        )

    jobs = []          # (index, uri, outbound | None)
    seen = set()

    for uri in candidates:
        key = dedupe_key(uri)
        if key in seen:
            continue
        seen.add(key)

        host, _ = uri_endpoint(uri)
        if not host or host.startswith("127.") or host in {"0.0.0.0", "localhost"}:
            continue   # заглушки

        outbound = make_singbox_outbound(uri)

        # то, что sing-box проверить не может (xhttp и т.п.), оставляем
        # только для vless: такие конфиги работают в Happ/xray
        if outbound is None and not uri.lower().startswith("vless://"):
            continue

        jobs.append((len(jobs) + 1, uri, outbound))

        if (
            MAX_CANDIDATES_TO_TEST_PER_SOURCE is not None
            and len(jobs) >= MAX_CANDIDATES_TO_TEST_PER_SOURCE
        ):
            break

    testable = [j for j in jobs if j[2] is not None]
    untestable = [j for j in jobs if j[2] is None]

    print(
        f"{source['name']}: {len(testable)} testable, "
        f"{len(untestable)} untestable (xhttp etc.)"
    )

    passed = []        # (latency, uri, stability)
    failed = []
    closed = set()
    reasons = {}
    skipped_by_time = 0
    deadline = time.monotonic() + SOURCE_TIME_BUDGET

    # случайный порядок, чтобы лимит по времени не резал одни и те же конфиги
    random.shuffle(testable)

    def work(index, uri, outbound):
        if time.monotonic() > deadline:
            return index, uri, None, "skipped"

        # быстрый отсев: если TCP-порт сервера закрыт, sing-box запускать не надо
        # (для hysteria2 это UDP, поэтому TCP-проверка только для vless)
        if outbound["type"] == "vless" and not tcp_open(
            outbound["server"], outbound["server_port"]
        ):
            return index, uri, None, "tcp port closed"

        result, reason = probe_through_singbox(outbound)

        # второй заход: бесплатные узлы часто отвечают не с первого раза
        # (нестабильные конфиги повторно не проверяем: они и так отсеяны)
        if (
            result is None
            and not reason.startswith("config rejected")
            and not reason.startswith("unstable")
        ):
            time.sleep(1)
            result, reason = probe_through_singbox(outbound)

        return index, uri, result, reason

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [
            pool.submit(work, index, uri, outbound)
            for index, uri, outbound in testable
        ]

        for future in as_completed(futures):
            index, uri, result, reason = future.result()

            if reason == "skipped":
                skipped_by_time += 1
                continue

            if result is not None:
                latency, stability = result
                print(
                    f"{source['name']} #{index}: PASS "
                    f"({latency:.2f}s, stable {stability:.0%})"
                )
                passed.append((latency, uri, stability))
            else:
                print(f"{source['name']} #{index}: FAIL - {reason}")
                failed.append((index, uri))

                if reason == "tcp port closed":
                    closed.add(index)

                kind = reason.split(":")[0][:30]
                reasons[kind] = reasons.get(kind, 0) + 1

    if skipped_by_time:
        print(
            f"WARNING: {source['name']}: {skipped_by_time} configs not checked "
            f"(SOURCE_TIME_BUDGET={SOURCE_TIME_BUDGET}s exceeded)"
        )

    # сначала самые стабильные, потом ближайшие к аудитории, потом по замеру
    # (пинг с раннера из США для пользователей не показателен)
    geo = geolocate({uri_endpoint(uri)[0] for _, uri, _ in passed})
    passed.sort(
        key=lambda item: (
            -round(item[2], 2),
            geo_bucket(item[1], geo),
            item[0],
        )
    )

    if reasons:
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(reasons.items()))
        print(f"{source['name']}: failure reasons -> {summary}")

    print(f"{source['name']}: {len(passed)} stable, best:")
    top_n = 10 if limit is None else limit + 3
    for latency, uri, stability in passed[:top_n]:
        host, _ = uri_endpoint(uri)
        est, country = estimate_ping_ms(host, geo)
        print(
            f"    stable {stability:.0%}, ~{est:.0f} ms from audience ({country}), "
            f"runner {latency:.2f}s  {host}"
        )

    if limit is None:
        selected = [uri for _, uri, _ in passed]
    else:
        selected = [uri for _, uri, _ in passed[:limit]]

    verified = len(selected)

    # режим без лимитов: только прошедшие проверку.
    # Непроверяемые (xhttp и т.п.) добавляются лишь по флагу INCLUDE_UNTESTABLE.
    if limit is None:
        if INCLUDE_UNTESTABLE:
            for index, uri, _ in untestable:
                host, port = uri_endpoint(uri)
                if tcp_open(host, port):
                    print(f"{source['name']} #{index}: UNTESTABLE (tcp open, added)")
                    selected.append(uri)

        print(
            f"{source['name']}: selected {len(selected)} configs "
            f"({verified} verified, {len(selected) - verified} unverified)"
        )
        return selected

    # добираем непроверенными, если источник это разрешает: в первую очередь
    # xhttp-конфиги, которые sing-box проверить не может. Берём серверы
    # с открытым TCP-портом, ближайшие к аудитории идут первыми
    if source.get("fill_unverified") and len(selected) < limit:
        pool_unverified = [
            (index, uri) for index, uri in failed if index not in closed
        ] + [(index, uri) for index, uri, _ in untestable]

        # hy2 работает по UDP, TCP-пинг к нему не показателен: в добор не берём
        pool_unverified = [
            item for item in pool_unverified
            if item[1].lower().startswith("vless://")
        ]

        def rtt_of(item):
            host, port = uri_endpoint(item[1])
            return item, tcp_rtt(host, port)

        ranked = []

        with ThreadPoolExecutor(max_workers=8) as rtt_pool:
            for item, rtt in rtt_pool.map(rtt_of, pool_unverified):
                if rtt is not None:
                    ranked.append((rtt, item))

        geo_fill = geolocate({uri_endpoint(item[1])[0] for _, item in ranked})
        ranked.sort(
            key=lambda entry: (geo_bucket(entry[1][1], geo_fill), entry[0])
        )

        for rtt, (index, uri) in ranked:
            if len(selected) >= limit:
                break

            print(
                f"{source['name']} #{index}: UNVERIFIED "
                f"(tcp {rtt * 1000:.0f} ms, added as filler)"
            )
            selected.append(uri)

    if len(selected) < limit:
        print(
            f"WARNING: {source['name']}: only {len(selected)} configs "
            f"(wanted {limit})"
        )

    print(
        f"{source['name']}: selected {len(selected)} configs "
        f"({verified} verified, {len(selected) - verified} unverified)"
    )
    return selected


def print_environment():
    """Диагностика раннера: версии, прямой доступ в интернет, страна/провайдер."""
    print("=== environment ===")

    for name, cmd in (
        ("sing-box", [SING_BOX, "version"]),
        ("curl", ["curl", "--version"]),
    ):
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            ).stdout.strip().splitlines()
            print(f"{name}: {out[0] if out else 'no output'}")
        except Exception as exc:
            print(f"{name}: ERROR {exc}")

    try:
        result = subprocess.run(
            [
                "curl", "--silent", "--max-time", "8",
                "--output", "/dev/null", "--write-out", "%{http_code}",
                "https://www.gstatic.com/generate_204",
            ],
            capture_output=True, text=True, timeout=12,
        )
        print(f"direct gstatic probe (no proxy): http={result.stdout.strip()} rc={result.returncode}")
    except Exception as exc:
        print(f"direct probe: ERROR {exc}")

    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=8) as response:
            info = json.loads(response.read().decode("utf-8", errors="replace"))
        print(
            f"runner location: {info.get('country')} / {info.get('region')} / "
            f"{info.get('org')}"
        )
    except Exception as exc:
        print(f"runner location: unknown ({exc})")

    print("===================")


def main():
    print_environment()

    profiles = []   # по одному xray-JSON на источник

    for source in SOURCES:
        try:
            uris = get_working(source)
        except Exception as exc:
            print(f"ERROR in source {source['name']}: {exc}")
            continue

        profile = build_happ_json(
            source["name"],
            uris,
            source.get("allow_hysteria", False),
            source.get("title"),
        )

        if profile is None:
            print(
                f"{source['name']}: no configs convertible to xray JSON, skipping"
            )
            continue

        count = len(profile["outbounds"]) - 2   # минус direct и block
        skipped = len(uris) - count
        print(
            f"{source['name']}: JSON profile with {count} configs "
            f"({skipped} skipped: unsupported)"
        )
        profiles.append(profile)

    if len(profiles) < MIN_TOTAL_TO_WRITE:
        print("No working configs found; keeping existing cat.txt")
        sys.exit(1)

    # ВАЖНО: только чистый JSON, без #-заголовков, иначе Happ не распознает подписку
    body = json.dumps(profiles, ensure_ascii=False, indent=2)
    OUTPUT_FILE.write_text(body + "\n", encoding="utf-8")

    print(f"Done: wrote {len(profiles)} JSON profiles to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
