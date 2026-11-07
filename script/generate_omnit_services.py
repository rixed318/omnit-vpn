#!/usr/bin/env python3
"""Build the reviewed OMNIT service catalog from domain-list-community.

The input repository is never bundled. The generated JSON records its commit
and contains only normalized domain suffixes plus OMNIT's product metadata.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


CATEGORIES = {
    "ИИ": "openai anthropic google-gemini github-copilot perplexity poe deepseek huggingface cursor xai jetbrains-ai apple-intelligence bytedance-ai-!cn xiaomi-ai aixcoder",
    "Разработка": "github gitlab bitbucket docker npmjs nodejs sourceforge jetbrains vercel heroku digitalocean aws azure oracle cloudflare canonical debian archlinux",
    "Социальные сети": "instagram facebook threads twitter tiktok reddit pinterest bluesky mastodon linkedin snapchat tumblr flickr quora medium pixiv weibo xiaohongshu",
    "Мессенджеры": "telegram whatsapp signal viber line wechat imo matrix threema discord messenger skype kakao qq zalo session",
    "Видео": "capcut youtube twitch vimeo dailymotion kick bilibili trovo peertube niconico iqiyi youku douyu huya abema",
    "Музыка": "spotify apple-music deezer tidal soundcloud bandcamp pandora tunein lastfm youtube-music qobuz iheart",
    "Стриминг": "netflix disney hbo hulu primevideo paramountplus peacock appletv crunchyroll discoveryplus mubi plex",
    "Игры": "steam epicgames gog ea ubisoft riot blizzard playstation xbox nintendo faceit wargaming roblox minecraft hoyoverse supercell",
    "Облака": "google-drive dropbox onedrive icloud box mega pcloud protondrive sync mediafire",
    "Поиск": "google bing duckduckgo brave startpage yahoo-search swisscows ecosia",
    "Карты": "google-maps openstreetmap mapbox waze here 2gis mapquest maps-me",
    "Почта": "gmail outlook protonmail tutanota zoho mailcom yahoo-mail mailru fastmail gmx",
    "Новости": "reuters apnews cnn bbc theguardian nytimes washingtonpost bloomberg aljazeera dw france24 euronews meduza rbc",
    "Образование": "coursera udemy edx khanacademy wikipedia duolingo quizlet skillshare stepik geekbrains",
    "Работа": "notion slack atlassian miro trello asana clickup monday figma canva airtable basecamp zapier linear whop",
    "Видеосвязь": "zoom microsoft-teams google-meet webex gotomeeting jitsi loom whereby",
    "Магазины": "amazon aliexpress ebay temu shein ozon wildberries avito etsy walmart bestbuy booking airbnb ikea adidas nike uniqlo hm",
    "Платежи": "paypal wise revolut stripe payoneer westernunion mastercard visa unionpay klarna afterpay alipay",
    "Криптовалюты": "bingx binance bybit okx kucoin coinbase kraken ton blockchain metamask ledger",
    "Android": "google-play googlefcm android apkpure apkmirror",
    "Российские сервисы": "vk dzen rutube yandex ok kinopoisk 4pda hh ivi rambler pikabu habr vc cian kwork",
    "Банки": "sber tinkoff alfabank vtb gazprombank raiffeisenbank qiwi yoomoney",
    "Государственные сервисы": "gosuslugi nalog mosru kremlin rosreestr",
    "Безопасность": "ip-checkers bitwarden 1password protonvpn mullvad nordvpn",
}

DOMAIN_OVERRIDES = {
    "ip-checkers": "2ip.io 2ip.ru browserleaks.com browserleaks.io db-ip.com dnscheck.tools dnsleaktest.com icanhazip.com ifconfig.is ifconfig.me ip-api.com ip-score.com ip.me ipcheck.ing ipchicken.com ipchicken.io iphey.com ipify.org ipinfo.io iplocation.com iplocation.net ipqualityscore.com ipleak.net mxtoolbox.com myip.com pixelscan.net proxycheck.io scamalytics.com whatismyip.com whatismyip.codes whatismyip.technology whatismyipaddress.com whatleaks.com whoer.com whoer.net",
    "whop": "whop.com whop.io whop-assets.com contentrewards.com",
    "openai": "chat.com chatgpt.com chatgpt.livekit.cloud host.livekit.cloud oaistatic.com oaiusercontent.com openai.com sora.com turn.livekit.cloud",
    "github": "github.com githubassets.com githubusercontent.com",
    "instagram": "instagram.com cdninstagram.com ig.me igcdn.com",
    "facebook": "facebook.com fbcdn.net messenger.com",
    "twitter": "x.com twitter.com twimg.com",
    "tiktok": "tiktok.com tiktokcdn.com tiktokv.com byteoversea.com ibytedtos.com muscdn.com",
    "capcut": "capcut.com capcut.net capcutapi.com isnssdk.com byteoversea.net byteeffecttos-g.com bytegecko-i18n.com pitaya-clientai.com ibyteimg.com",
    "linkedin": "linkedin.com licdn.com",
    "telegram": "telegram.org telegram.me telegram.dog telegram-cdn.org t.me telegra.ph tdesktop.com",
    "discord": "discord.com discord.gg discordapp.com discordapp.net discordcdn.com",
    "youtube": "youtube.com youtu.be googlevideo.com ytimg.com youtube-nocookie.com ggpht.com",
    "spotify": "spotify.com scdn.co spotifycdn.com",
    "disney": "disneyplus.com disney-plus.net dssott.com",
    "hulu": "hulu.com huluim.com",
    "vk": "vk.com vk.ru vkvideo.ru vkuser.net vkuseraudio.net vkuserlive.net vkuservideo.net vkcdnservice.com userapi.com",
    "yandex": "yandex.ru yandex.com yandex.net yastatic.net yandexcloud.net",
    "mailru": "mail.ru ok.ru mycdn.me imgsmail.ru",
    "sber": "sber.ru sberbank.ru sberbank.com sberdevices.ru sbercloud.ru",
    "bitbucket": "bitbucket.org bitbucket.io",
    "mastodon": "joinmastodon.org mastodon.social mastodon.online",
    "snapchat": "snapchat.com sc-cdn.net snap.com",
    "weibo": "weibo.com weibo.cn sinaimg.cn",
    "wechat": "wechat.com weixin.com weixin.qq.com",
    "imo": "imo.im imoapp.com",
    "threema": "threema.ch",
    "skype": "skype.com skype.net skypeassets.com",
    "qq": "qq.com qpic.cn gtimg.cn",
    "zalo": "zalo.me zaloapp.com zalo.cloud",
    "session": "getsession.org",
    "trovo": "trovo.live",
    "peertube": "joinpeertube.org peertube.tv",
    "pandora": "pandora.com",
    "tunein": "tunein.com radiotime.com",
    "youtube-music": "music.youtube.com",
    "qobuz": "qobuz.com",
    "iheart": "iheart.com iheartmedia.com",
    "paramountplus": "paramountplus.com cbsi.com",
    "peacock": "peacocktv.com",
    "appletv": "tv.apple.com",
    "crunchyroll": "crunchyroll.com crunchyrollcdn.com",
    "minecraft": "minecraft.net mojang.com",
    "xbox": "xbox.com xboxlive.com xboxservices.com",
    "google-drive": "drive.google.com docs.google.com drive.usercontent.google.com",
    "box": "box.com boxcdn.net",
    "pcloud": "pcloud.com pcloud.link",
    "protondrive": "drive.proton.me protondrive.com",
    "sync": "sync.com",
    "mediafire": "mediafire.com",
    "google": "www.google.com google.ru",
    "brave": "brave.com bravebrowser.com bravecdn.com",
    "yahoo-search": "search.yahoo.com",
    "swisscows": "swisscows.com",
    "ecosia": "ecosia.org",
    "google-maps": "maps.google.com maps.gstatic.com",
    "waze": "waze.com",
    "here": "here.com hereapi.com",
    "mapquest": "mapquest.com mapquestapi.com",
    "maps-me": "maps.me",
    "gmail": "mail.google.com gmail.com googlemail.com",
    "outlook": "outlook.com outlook.live.com",
    "yahoo-mail": "mail.yahoo.com",
    "fastmail": "fastmail.com fastmailusercontent.com",
    "gmx": "gmx.com gmx.net",
    "apnews": "apnews.com",
    "washingtonpost": "washingtonpost.com",
    "france24": "france24.com",
    "euronews": "euronews.com",
    "rbc": "rbc.ru rbcgroup.ru",
    "wikipedia": "wikipedia.org wikimedia.org",
    "quizlet": "quizlet.com",
    "stepik": "stepik.org",
    "geekbrains": "gb.ru geekbrains.ru",
    "miro": "miro.com mirostatic.com",
    "atlassian": "atlassian.com atlassian.net statuspage.io",
    "trello": "trello.com trello.services",
    "asana": "asana.com",
    "clickup": "clickup.com",
    "monday": "monday.com",
    "airtable": "airtable.com airtableusercontent.com",
    "basecamp": "basecamp.com basecampapi.com",
    "zapier": "zapier.com",
    "linear": "linear.app linearusercontent.com",
    "microsoft-teams": "teams.microsoft.com teams.live.com",
    "google-meet": "meet.google.com",
    "gotomeeting": "gotomeeting.com goto.com",
    "jitsi": "meet.jit.si jitsi.org",
    "loom": "loom.com loomcdn.com",
    "whereby": "whereby.com",
    "aliexpress": "aliexpress.com alicdn.com",
    "temu": "temu.com temucdn.com",
    "shein": "shein.com sheincdn.com",
    "etsy": "etsy.com etsystatic.com",
    "uniqlo": "uniqlo.com",
    "revolut": "revolut.com",
    "payoneer": "payoneer.com",
    "westernunion": "westernunion.com",
    "klarna": "klarna.com",
    "afterpay": "afterpay.com",
    "alipay": "alipay.com alipayobjects.com",
    "bingx": "bingx.com api-app.we-api.com api-swap.we-api.com ws-market-swap.we-api.com bin.bb-os.com static-app.bb-os.com api-app.qq-os.com api-app.acc-de.com api-swap.acc-de.com api-app.tra-eo.com api-app-aip-1.tra-eo.com api-swap.tra-eo.com bon-prod-guance.great-api.com",
    "coinbase": "coinbase.com coinbaseassets.com",
    "ton": "ton.org tonkeeper.com",
    "blockchain": "blockchain.com blockchain.info",
    "metamask": "metamask.io",
    "ledger": "ledger.com ledgerwallet.com",
    "hh": "hh.ru",
    "ivi": "ivi.ru",
    "rambler": "rambler.ru",
    "pikabu": "pikabu.ru",
    "vc": "vc.ru",
    "kwork": "kwork.ru",
    "tinkoff": "tbank.ru tinkoff.ru",
    "alfabank": "alfabank.ru",
    "vtb": "vtb.ru",
    "gazprombank": "gazprombank.ru gpb.ru",
    "qiwi": "qiwi.com",
    "yoomoney": "yoomoney.ru",
    "gosuslugi": "gosuslugi.ru",
    "nalog": "nalog.gov.ru",
    "mosru": "mos.ru",
    "kremlin": "kremlin.ru",
    "rosreestr": "rosreestr.gov.ru",
    "1password": "1password.com 1passwordusercontent.com",
    "protonvpn": "protonvpn.com protonvpn.net",
    "mullvad": "mullvad.net",
    "nordvpn": "nordvpn.com nordcdn.com",
}

TITLES = {
    "ip-checkers": "Проверка IP и утечек",
    "bingx": "BingX",
    "openai": "OpenAI / ChatGPT / Codex", "xai": "Grok / xAI", "capcut": "CapCut",
    "google-gemini": "Google Gemini", "github-copilot": "GitHub Copilot",
    "apple-intelligence": "Apple Intelligence", "bytedance-ai-!cn": "ByteDance AI",
    "npmjs": "npm", "xiaomi-ai": "Xiaomi AI", "twitter": "X / Twitter",
    "googlefcm": "Firebase Cloud Messaging", "google-play": "Google Play",
    "ok": "Одноклассники", "dzen": "Дзен", "2gis": "2GIS",
    "hh": "HH.ru", "vc": "VC.ru", "sber": "Сбер",
    "tinkoff": "Т-Банк", "nalog": "ФНС", "mosru": "Мос.ру",
    "1password": "1Password", "4pda": "4PDA",
}

PROXY_IDS = set("""
ip-checkers
openai anthropic google-gemini github-copilot perplexity poe xai jetbrains-ai
github sourceforge
instagram facebook threads twitter tiktok reddit linkedin snapchat capcut
telegram whatsapp signal viber discord
youtube twitch vimeo dailymotion kick
spotify apple-music deezer tidal soundcloud
netflix disney hbo hulu primevideo paramountplus peacock appletv
protonmail tutanota
reuters cnn bbc theguardian
paypal wise revolut
coinbase kraken
""".split())

SECURITY_IDS = set(CATEGORIES["Платежи"].split() + CATEGORIES["Криптовалюты"].split()
                   + CATEGORIES["Банки"].split() + CATEGORIES["Государственные сервисы"].split()
                   + CATEGORIES["Безопасность"].split()
                   + "gmail outlook protonmail tutanota mailru".split())

# These manually narrowed entries are stable first-party endpoints rather than
# inferred third-party CDNs. They can retain high confidence even though OMNIT
# intentionally overrides the broader community list for them.
HIGH_CURATED_IDS = set("""
ip-checkers
openai github instagram facebook twitter tiktok linkedin telegram discord youtube spotify capcut
disney hulu xbox minecraft atlassian
vk yandex mailru sber gosuslugi nalog mosru rosreestr
""".split())

FORBIDDEN_SUFFIXES = {
    "google.com", "googleapis.com", "amazonaws.com", "cloudflare.com",
    "microsoft.com", "akamai.net",
}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9!@-]*$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def title_for(service_id: str) -> str:
    return TITLES.get(service_id, service_id.replace("-!cn", "").replace("-", " ").title())


def description_for(service_id: str) -> str:
    if service_id == "ip-checkers":
        return "IP, DNS, WebRTC, fingerprint и proxy-check страницы — по умолчанию только через VPN"
    return f"Маршрутизация доменов сервиса {title_for(service_id)}"


def domains_from_file(data_dir: Path, service_id: str, seen: set[str] | None = None) -> set[str]:
    seen = set() if seen is None else seen
    if service_id in seen:
        return set()
    seen.add(service_id)
    path = data_dir / service_id
    if not path.is_file():
        return set()
    result: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        if "@ads" in value.split()[1:]:
            continue
        value = value.split()[0]
        if value.startswith("include:"):
            result.update(domains_from_file(data_dir, value[8:], seen))
            continue
        if value.startswith(("regexp:", "keyword:")):
            continue
        if value.startswith("full:"):
            value = value[5:]
        elif value.startswith("domain:"):
            value = value[7:]
        value = value.lower().rstrip(".")
        if DOMAIN_RE.fullmatch(value) and value not in FORBIDDEN_SUFFIXES:
            result.add(value)
    return result


def validate(services: list[dict]) -> None:
    ids = [item["id"] for item in services]
    if len(ids) != 284 or len(set(ids)) != 284:
        raise ValueError(f"Expected 284 unique services, got {len(ids)}/{len(set(ids))}")
    if len(CATEGORIES) != 24:
        raise ValueError(f"Expected 24 categories, got {len(CATEGORIES)}")
    domain_owners: dict[str, str] = {}
    for item in services:
        if not ID_RE.fullmatch(item["id"]):
            raise ValueError(f"Invalid id: {item['id']}")
        if not item["domainSuffixes"]:
            raise ValueError(f"Service has no domains: {item['id']}")
        for domain in item["domainSuffixes"]:
            if domain in FORBIDDEN_SUFFIXES or not DOMAIN_RE.fullmatch(domain):
                raise ValueError(f"Unsafe domain for {item['id']}: {domain}")
            if domain in domain_owners:
                raise ValueError(
                    f"Domain belongs to both {domain_owners[domain]} and {item['id']}: {domain}"
                )
            domain_owners[domain] = item["id"]
    if sum(item["countryModes"]["RU"]["mode"] == "proxy" for item in services) != 54:
        raise ValueError("RU preset must contain exactly 54 proxy services")
    if sum(item["securitySensitive"] for item in services) != 47:
        raise ValueError("Catalog must contain exactly 47 security-sensitive services")
    confidence = [item["countryModes"]["RU"]["confidence"] for item in services]
    if confidence.count("high") != 183 or confidence.count("medium") != 101:
        raise ValueError("Catalog confidence distribution must be 183 high / 101 medium")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_list", type=Path, help="domain-list-community checkout")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data_dir = args.domain_list / "data"
    if not data_dir.is_dir():
        raise SystemExit("domain-list-community/data was not found")
    commit = subprocess.run(
        ["git", "-C", str(args.domain_list), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    services: list[dict] = []
    for category, raw_ids in CATEGORIES.items():
        for service_id in raw_ids.split():
            if service_id in DOMAIN_OVERRIDES:
                domains = set(DOMAIN_OVERRIDES[service_id].split())
                evidence = "curated-first-party"
            else:
                domains = domains_from_file(data_dir, service_id)
                evidence = "domain-list-community"
            mode = "proxy" if service_id in PROXY_IDS else "direct"
            services.append({
                "id": service_id,
                "title": title_for(service_id),
                "description": description_for(service_id),
                "category": category,
                "domainSuffixes": sorted(domains),
                "processNames": ["Telegram"] if service_id == "telegram" else [],
                "ruleSets": [],
                "securitySensitive": service_id in SECURITY_IDS,
                "countryModes": {
                    "RU": {
                        "mode": mode,
                        "confidence": (
                            "high"
                            if evidence == "domain-list-community" or service_id in HIGH_CURATED_IDS
                            else "medium"
                        ),
                        "reason": (
                            "Скрывать direct IP при проверках приватности и утечек"
                            if service_id == "ip-checkers"
                            else (
                                "Требует VPN или иностранного региона в российском пресете"
                                if mode == "proxy" else "По умолчанию используется прямое соединение"
                            )
                        ),
                    }
                },
                "evidence": evidence,
            })
    # A destination may belong to only one switch. This prevents contradictory
    # user choices (for example AWS vs Amazon or Bitbucket vs Atlassian) from
    # depending on incidental rule order. Earlier, more specific catalog
    # entries own shared endpoints; umbrella services retain their unique ones.
    claimed_domains: dict[str, str] = {}
    for service in services:
        unique_domains = []
        for domain in service["domainSuffixes"]:
            if domain in claimed_domains:
                continue
            claimed_domains[domain] = service["id"]
            unique_domains.append(domain)
        service["domainSuffixes"] = unique_domains
    validate(services)
    payload = {
        "schemaVersion": 1,
        "datasetId": "omnit-curated-services-ru",
        "generatedAt": "2026-08-23",
        "defaultCountry": "RU",
        "defaultMode": "direct",
        "sources": [{
            "name": "v2fly/domain-list-community",
            "url": "https://github.com/v2fly/domain-list-community",
            "commit": commit,
        }],
        "services": services,
        "recommendedFutureCountries": ["CN", "IR", "TM", "MM", "BY", "PK", "TR", "AE", "SA"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(services)} services from {commit} to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
