import base64
import socket
import urllib.request
from urllib.parse import urlsplit, unquote

SOURCE_URL = "https://gidroksi.fun/free"
OUTPUT_FILE = "cat.txt"
MAX_CONFIGS = 10
TIMEOUT = 4

HEADER = """#profile-title: Кошка жена ВПН 🐈
#profile-update-interval: 1
#subscription-userinfo: expire=86877705600; total=10995116277760; used=0
#profile-web-page-url: https://t.me/halyava_vpnx
#announce: 👲 Партия выдать тебе кошка жена + полный миска рис

"""


def download_subscription():
    request = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": "Mozilla/5.0"}
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        content = response.read().decode("utf-8").strip()

    try:
        decoded = base64.b64decode(
            content + "=" * (-len(content) % 4)
        ).decode("utf-8")

        if "://" in decoded:
            return decoded
    except Exception:
        pass

    return content


def get_server(config):
    try:
        parsed = urlsplit(config.strip())
        return parsed.hostname, parsed.port
    except Exception:
        return None, None


def is_russian(config):
    return "🇷🇺" in unquote(config)


def is_available(config):
    host, port = get_server(config)

    if not host or not port:
        return False

    try:
        with socket.create_connection(
            (host, port),
            timeout=TIMEOUT
        ):
            return True
    except (OSError, ValueError):
        return False


def main():
    print("Downloading subscription...")

    data = download_subscription()

    configs = []

    for line in data.splitlines():
        line = line.strip()

        if not line.startswith("vless://"):
            continue

        if is_russian(line):
            print("Skipped Russian config")
            continue

        if line in configs:
            continue

        configs.append(line)

    print(f"Found {len(configs)} VLESS configs")

    working = []

    for config in configs:
        if len(working) >= MAX_CONFIGS:
            break

        print("Checking config...")

        if is_available(config):
            working.append(config)
            print("Available!")
        else:
            print("Unavailable")

    if not working:
        raise RuntimeError(
            "No available configs. Previous cat.txt preserved."
        )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write(HEADER)
        file.write("\n".join(working))
        file.write("\n")

    print(f"Finished! Saved {len(working)} configs.")


if __name__ == "__main__":
    main()
