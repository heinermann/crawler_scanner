"""Functions to determine which URLs to ignore"""
import re
from urllib.parse import urlparse


BANNED_URLS = set()
with open("banned_urls.txt", "r", encoding="utf-8") as banned:
    BANNED_URLS = set(line.strip() for line in banned)


BANNED_REGEXES = [re.compile(s, re.IGNORECASE) for s in [
    r".*_mp3\.zip$",
    r".*/(handouts|slides).zip\".*",
    r".*/albums?/.*",
    r".*/audio/.*",
    r".*/comics?/.*",
    r".*/docs?/.*",
    r".*/drivers?/.*",
    r".*/dvd\b.*/.*",
    r".*/(e|e-)?books?/.*",
    r".*/fonts?/.*",
    r".*/index.scm(\??.*)$",
    r".*/lessons?/.*",
    r".*/literature/.*",
    r".*/magazines?/.*",
    r".*/manuals?/.*",
    r".*/midi/.*",
    r".*/graphics/.*",
    r".*/mixtapes/.*",
    r".*/movies?/.*",
    r".*/mp3s?/.*",
    r".*/music/.*",
    r".*/bible/.*",
    r".*/bibliography.*",
    r".*/patch(es)?/.*",
    r".*/pdf/.*",
    r".*/pdfs?/.*",
    r".*/photos?/.*",
    r".*/fotos?/.*",
    r".*/lectures?/.*",
    r".*/roms?/.*",
    r".*/rss/.*",
    r".*/vod/.*",
    r".*/spellchecker/.*",
    r".*/trainers?/.*",
    r".*/(utils?|utilities)/.*",
    r".*/screensavers?/.*",
    r".*/setup/.*",
    r".*/skins?/.*",
    r".*/financials?/.*",
    r".*/songs?/.*",
    r".*/sounds?/.*",
    r".*/temp/IndianJ\w+.*",
    r".*/temp/SaudiJ\w+.*",
    r".*/themes?/.*",
    r".*/videos?/.*",
    r".*\bgimp/.*",
    r".*wallpaper.*",
    r".*Encycopedia\.Britannica.*",
    r".*\.([a-z_]{3}|x86|x64|d64|3gp|mp3|mp4|m4v|wdgt|flst|jpeg|mpeg|com_|ppsx|docx|divx|html|aiff|cpp_|xvid)\.(zip|rar)$",
    r".*[._\-+](xvid|hdtv|480p|720p|1080p|x264|dvdrip|bluray|mixtape|(%5b|%28)dis[ck]\+[123])[._\-+].*",
    r".*_(win|osx|mac|src|exe|cs2|png|pps|dos|doc|fsx|jpg|x64|x86|php|css|img|wmv|pdf|vbs|psd|tif|dvd|gif|xml|xls|dwg|ttf|vlm|dxf|cad|com|linux|jar|pc|dll)\.(zip|rar)$",
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
    r".*photoshop.*",
    r".*subtitles?\..*",
    r"^e?books\..*",
    r"^mp3\..*",
]]


def should_ignore_site(url_raw: str) -> bool:
    """Checks if a URL should be ignored or not."""

    url = urlparse(url_raw)
    netloc = url.netloc.lower()
    if netloc in BANNED_URLS:
        return True

    for r in BANNED_DOMAIN_REGEXES:
        if r.match(netloc):
            return True

    for r in BANNED_REGEXES:
        if r.match(url_raw):
            return True

    return False
