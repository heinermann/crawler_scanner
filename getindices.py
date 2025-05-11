#!/usr/bin/env python3
import gzip
import io
import json
import re
from urllib.parse import urlparse

import requests
from tqdm import tqdm


COMMON_CRAWL_S3_BASE_URL = "https://data.commoncrawl.org/"
CUSTOM_USER_AGENT = "Mozilla/5.0 (compatible; CustomDownloader/0.1; +https://github.com/heinermann/crawler_scanner)"
REGEX = r' \{.*"url":\s*"[^"]*\.(scm|scx|rep|pud|zip|rar)(\?[^"#]*|#[^"#]*)?".*\}$'
PATTERN = re.compile(REGEX)


BANNED_URLS = set()
with open("banned_urls.txt", "r", encoding="utf-8") as banned:
    BANNED_URLS = set(line.strip() for line in banned)


BANNED_REGEXES = [re.compile(s, re.IGNORECASE) for s in [
    r".*_mp3\.zip$",
    r".*/MP3/.*",
    r".*/mp3s/.*",
    r".*/screensavers/.*",
    r".*/pdf/.*",
    r".*/skins/.*",
    r".*/themes/.*",
    r".*/music/.*",
    r".*/mixtapes/.*",
    r".*/comics/.*",
    r".*/audio/.*",
    r".*/video/.*",
    r".*wallpaper.*",
    r".*/temp/IndianJ\w+.*",
    r".*/temp/SaudiJ\w+.*",
]]

BANNED_DOMAIN_REGEXES = [re.compile(s, re.IGNORECASE) for s in [
    r".*\.wincustomize\.com$",
    r".*\.sourceforge\.net$",
    r".*\.cheaters-heaven\.com$",
    r".*\.gov(\.\w+)?$",
]]


class CountingReader(io.RawIOBase):
    def __init__(self, raw):
        self.raw = raw
        self.bytes_read = 0

    def read(self, size=-1):
        data = self.raw.read(size)
        self.bytes_read += len(data)
        return data

    def readable(self):
        return True


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


def read_index_line(line: str) -> dict[str, str] | None:
    match = PATTERN.search(line)
    if not match:
        return None

    try:
        data = json.loads(match.group(0))
    except Exception as e:
        print(f"FAILED JSON READ: {e}\nContent: {line}")

    # We don't care about redirects and failed pages, since they won't have any usable content
    if data.get("status") != "200":
        return None

    if should_ignore_site(data.get("url")):
        return None

    json_stripped = {key: data[key] for key in ("url", "offset", "length", "filename")}
    return json_stripped


def bytes_progress_bar(total: int, desc: str, position: int) -> tqdm:
    return tqdm(total=total,
                desc=desc,
                position=position,
                leave=True,
                mininterval=1.0,
                miniters=1,
                unit="B",
                unit_scale=True,
                unit_divisor=1024)


def read_index_file(idx_line: str, position: int, output_file: str) -> dict[str, int]:
    idx_line = idx_line.strip()
    if not idx_line:
        return

    header = {
        "user-agent": CUSTOM_USER_AGENT
    }
    r = requests.get(COMMON_CRAWL_S3_BASE_URL + idx_line, headers=header, timeout=(5, None), stream=True)
    total_size = int(r.headers.get("Content-Length", 0))

    r.iter_lines()
    counter = CountingReader(r.raw)

    results = []
    last_count = 0

    with gzip.GzipFile(fileobj=counter) as gz, io.TextIOWrapper(gz, encoding="utf-8") as reader:
        with bytes_progress_bar(total_size, idx_line, position) as progress_bar:
            for line in reader:
                processed_item = read_index_line(line)
                if processed_item is not None:
                    results.append(processed_item)

                progress_bar.update(counter.bytes_read - last_count)
                last_count = counter.bytes_read

    with open(output_file, "a", encoding="utf-8") as out:
        for line in results:
            print(json.dumps(line), file=out)


def get_indices(input_file: str, output_file: str) -> None:
    # clear output
    open(output_file, "w", encoding="utf-8").close()

    indices = None
    with open(input_file, "r", encoding="utf-8") as f:
        indices = f.readlines()

    with tqdm(total=len(indices), desc="Total", unit="", position=0, leave=True) as progress_bar:
        for i, item in enumerate(indices):
            read_index_file(item, i + 1, output_file)
            progress_bar.update(1)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Retrieve the indices for a crawl (filenames and archive locations) and filters it to target specific resources.")
    parser.add_argument("--input_file", default="cc-index.paths", help="Path to the input file (e.g., cc-index.paths)")
    parser.add_argument("output_file", help="File to print the filtered indices to")
    args = parser.parse_args()

    get_indices(args.input_file, args.output_file)
    print("\nProcessing complete.")
