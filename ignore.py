"""Functions to determine which URLs to ignore"""
import re
from urllib.parse import urlparse


BANNED_URLS = set()
with open("banned_urls.txt", "r", encoding="utf-8") as banned:
    BANNED_URLS = set(line.strip() for line in banned)


BANNED_PATHS_WITH_S = [
    "album",
    "background",
    "banner",
    "book",
    "chat",
    "chatroom",
    "comic",
    "conference",
    "decision",
    "digest",
    "disclaimer",
    "dll",
    "doc",
    "drawing",
    "driver",
    "e-book",
    "e-mail",
    "ebook",
    "email",
    "emulator",
    "exe",
    "exercise",
    "financial",
    "font",
    "foto",
    "gallerie",
    "graphic",
    "hebrew-font",
    "icon",
    "lecture",
    "lesson",
    "magazine",
    "mail",
    "manual",
    "material",
    "memoire",
    "mixtape",
    "model",
    "modem",
    "movie",
    "mp3",
    "musica",
    "musical",
    "newspaper",
    "pdf",
    "photo",
    "plugin",
    "powerpoint",
    "ppt",
    "presskit",
    "publication",
    "rom",
    "screencap",
    "screensaver",
    "skin",
    "song",
    "sound",
    "sprite",
    "style",
    "template",
    "text",
    "theme",
    "trainer",
    "util",
    "video",
    "wedding_font",
    "wp-theme",
    "dataset",
]

BANNED_PATHS = [
    "audio",
    "bible",
    "bibliography",
    "biblioteca",
    "bios",
    "blackberry",
    "brushes",
    "crypto",
    "devtools",
    "dotnet",
    "emulatoren",
    "firmware",
    "java",
    "literature",
    "manga",
    "midi",
    "music",
    "paypal",
    "pda",
    "photography",
    "presse",
    "rss",
    "sdk",
    "setup",
    "spellchecker",
    "supernatural",
    "telemetry",
    "tvshows",
    "vod",
    "wireless",
    "photoshop",
    "illustrator",
    "redirect",
    "dictionaries",
]

BANNED_TOKENS = [
    "album",
    "bluray",
    "divx",
    "dvdrip",
    "dvdscr",
    "ebook",
    "emudvd",
    "hdtv",
    "ipod",
    "mixtape",
    "mp3",
    "mp4",
    "osx",
    "setup",
    "soundtrack",
    "win32",
    "winexe",
    "x264",
    "xbox360",
    "xvid",
]

BANNED_REGEXES = [re.compile(s, re.IGNORECASE) for s in [
    r".*_mp3\.zip$",
    r".*/(handouts|slides).zip\".*",
    r".*/dvd\b.*/.*",
    r".*/index.scm(\??.*)$",
    r".*/patch(es)?/.*",
    r".*/(utility|utilities)/.*",
    r".*/temp/IndianJ\w+.*",
    r".*/temp/SaudiJ\w+.*",
    r".*\bgimp/.*",
    r".*wallpaper.*",
    r".*winamp.*",
    r".*payment\.php.*",
    r".*/book\.(zip|rar)$",
    r".*Encycopedia\.Britannica.*",
    r".*\.(x86|x64|d64|3gp|m4v|wdgt|flst|jpeg|mpeg|com_|ppsx|docx|html|aiff|cpp_)\.(zip|rar)$",
    r".*(%20|\b|_)(480[pi]|720[pi]|1080[pi]|(%5b|%28)dis[ck]\+[1234]|cd[1234]|dvd[1-9]?|part[2-9][0-9])(\b|_).*",
    r".*(%20|\b|_)(" + "|".join(BANNED_TOKENS) + r")(\b|_).*",
    r".*s\d\de\d\d[._\-+%].*",
    r".*[_\-](win|osx|mac|src|exe|cs2|png|pps|dos|doc|fsx|jpg|x64|x86|php|css|img|wmv|pdf|vbs|psd|tif|dvd|gif|xml|xls|dwg|ttf|vlm|dxf|cad|com|linux|jar|pc|dll)\.(zip|rar)$",
    f".*/({'|'.join(BANNED_PATHS_WITH_S)})s?/.*",
    f".*/({'|'.join(BANNED_PATHS)})/.*",
    r".*(1024|1152|1280|1600|1920|800)x(1024|1200|1440|600|768|864|960).*",
    r".*/(safelink|redirect)\.php\?.*",
]]

BANNED_DOMAIN_REGEXES = [re.compile(s, re.IGNORECASE) for s in [
    r".*\.ageofempires.*\..*",
    r".*\.blackberry.*\..*",
    r".*\.cheaters-heaven\.com$",
    r".*\.font.*",
    r".*\.gov(\.\w+)?$",
    r".*\.nokia\.com$",
    r".*\.codehaus\.org$",
    r".*\.sina\.com\.cn$",
    r"(.*\.|^)sourceforge\.net$",
    r".*\.state\.\w\w\.us$",
    r".*\.swipnet\.se$",
    r".*\.wincustomize\.com$",
    r".*\.deviantart\.net$",
    r".*fonts?\..*",
    r".*(photoshop|hentai|theme|iphone|javascript|facebook).*",
    r".*subtitles?\..*",
    r"^e?books\..*",
    r"^mp3\..*",
    r".*sims[1-6]?\..*",
    r"(.*\.|^)sims.*",
    r"(.*\.|^)gta.*",
    r"(.*\.|^)wedding.*",
    r"(.*\.|^)bible.*",
    r".*bible\..*",
    r"(.*\.|^)islam.*",
    r".*islam\..*",
]]


def should_ignore_site(url_raw: str) -> bool:
    """Checks if a URL should be ignored or not."""

    url = urlparse(url_raw)
    netloc = url.netloc.lower().split(":")[0]
    if netloc in BANNED_URLS:
        return True

    for r in BANNED_DOMAIN_REGEXES:
        if r.match(netloc):
            return True

    for r in BANNED_REGEXES:
        if r.match(url_raw):
            return True

    return False
