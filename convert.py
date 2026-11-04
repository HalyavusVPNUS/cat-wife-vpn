import base64
import urllib.request
from urllib.parse import urlsplit, unquote

SOURCE_URL = "https://freevpn.happcluchi.workers.dev"
OUTPUT_FILE = "cat.txt"

MAX_CONFIGS = 10

ALLOWED_SCHEMES = {
    "vless",
    "hy2",
    "hysteria2",
    "hysteria"
}

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

    with urllib.request.urlopen(request, timeout=40) as response:
        data = response.read().decode("utf-8-sig").strip()

    # Источник обычно отдаёт обычный текст.
    # Base64 оставлен как запасной вариант.
    if "://" not in data:
        try:
            compact = "".join(data.split())

            decoded = base64.b64decode(
                compact + "=" * (-len(compact) % 4),
                validate=True
            ).decode("utf-8-sig")

            if "://" in decoded:
                data = decoded

        except Exception:
            pass

    return data


def get_configs(data):
    vless = []
    hysteria = []

    seen = set()

    for line in data.splitlines():
        line = line.strip()

        if "://" not in line:
            continue

        scheme = line.split("://", 1)[0].lower()

        # Оставляем только нужные протоколы
        if scheme not in ALLOWED_SCHEMES:
            continue

        # Исключаем российские флаги
        if "🇷🇺" in unquote(line):
            continue

        # Проверяем адрес и порт
        try:
            parsed = urlsplit(line)

            if not parsed.hostname or not parsed.port:
                continue

            if parsed.hostname.lower() in (
                "localhost",
                "127.0.0.1"
            ):
                continue

        except ValueError:
            continue

        # Убираем дубликаты
        if line in seen:
            continue

        seen.add(line)

        if scheme == "vless":
            vless.append(line)
        else:
            hysteria.append(line)

    return vless, hysteria


def select_configs(vless, hysteria):
    selected = []

    # Стараемся распределить 10 конфигов
    # между двумя протоколами поровну.
    quota = MAX_CONFIGS // 2

    for i in range(quota):
        if i < len(vless):
            selected.append(vless[i])

        if i < len(hysteria):
            selected.append(hysteria[i])

    # Если одного протокола мало,
    # добираем конфиги из другого.
    if len(selected) < MAX_CONFIGS:
        remaining = (
            vless[quota:] +
            hysteria[quota:]
        )

        selected.extend(
            remaining[:MAX_CONFIGS - len(selected)]
        )

    return selected


def save_subscription(configs):
    if not configs:
        raise RuntimeError(
            "No VLESS or Hysteria configs found!"
        )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(HEADER)
        file.write("\n".join(configs))
        file.write("\n")

    print(f"Saved {len(configs)} configs!")

    print(
        "VLESS:",
        sum(c.startswith("vless://") for c in configs)
    )

    print(
        "Hysteria:",
        sum(
            c.startswith((
                "hy2://",
                "hysteria2://",
                "hysteria://"
            ))
            for c in configs
        )
    )


def main():
    print("Downloading subscription...")

    data = download_subscription()

    vless, hysteria = get_configs(data)

    print(f"Found VLESS: {len(vless)}")
    print(f"Found Hysteria: {len(hysteria)}")

    configs = select_configs(vless, hysteria)

    save_subscription(configs)


if __name__ == "__main__":
    main()
