#!/usr/bin/env python3
import gzip
import io
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from tqdm import tqdm


COMMON_CRAWL_S3_BASE_URL = "https://data.commoncrawl.org/"
REGEX = r'\{"url":\s*"[^"]*\.(scm|scx|rep|pud|zip|rar)(\?[^"#]*|#[^"#]*)?".*\}$'
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
    r".*/music/.*",
    r".*/mixtapes/.*",
    r".*/comics/.*",
    r".*/audio/.*",
    r".*\.wincustomize\.com/.*",
    r".*wallpaper.*",
    r".*/temp/IndianJ\w+.*",
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

    if netloc.endswith(".gov") or netloc.endswith("sourceforge.net"):
        return True

    for r in BANNED_REGEXES:
        if r.match(url_raw):
            return True

    return False


def read_index_line(line: str) -> dict[str, str] | None:
    match = PATTERN.search(line)
    if not match:
        return None

    data = json.loads(match.group(0))

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


def read_index_file(idx_line: str, position: int) -> list[dict[str, str]]:
    idx_line = idx_line.strip()
    if not idx_line:
        return []

    r = requests.get(COMMON_CRAWL_S3_BASE_URL + idx_line, timeout=(5, None), stream=True)
    total_size = int(r.headers.get("Content-Length", 0))

    results = []
    counter = CountingReader(r.raw)
    last_count = 0
    with gzip.GzipFile(fileobj=counter) as gz, io.TextIOWrapper(gz, encoding="utf-8") as reader:
        with bytes_progress_bar(total_size, idx_line, position) as progress_bar:
            for line in reader:
                processed_item = read_index_line(line)
                if processed_item is not None:
                    results.append(processed_item)

                progress_bar.update(counter.bytes_read - last_count)
                last_count = counter.bytes_read

            progress_bar.display()
            progress_bar.close()

    return list(filter(None, results))  # Removes all None items


def get_indices(input_file: str, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as out, open(input_file, "r", encoding="utf-8") as f:
        indices = f.readlines()

        results = []
        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = []
            for i, item in enumerate(indices):
                futures.append(executor.submit(read_index_file, item, i + 1))

            for future in tqdm(as_completed(futures), desc="Total", unit="", total=len(futures), position=0, leave=True):
                results += future.result()

        for item in results:
            print(json.dumps(item), file=out)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Retrieve the indices for a crawl (filenames and archive locations) and filters it to target specific resources.")
    parser.add_argument("input_file", required=True, default="cc-index.paths", help="Path to the input file (e.g., cc-index.paths)")
    parser.add_argument("output_file", required=True, help="File to print the filtered indices to")
    args = parser.parse_args()

    get_indices(args.input_file, args.output_file)
    print("\nProcessing complete.")
