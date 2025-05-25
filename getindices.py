#!/usr/bin/env python3
import gzip
import io
import os
import json
import re

import requests
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util import Retry

from ignore import should_ignore_site


COMMON_CRAWL_S3_BASE_URL = "https://data.commoncrawl.org/"
CUSTOM_USER_AGENT = "Mozilla/5.0 (compatible; CustomDownloader/0.1; +https://github.com/heinermann/crawler_scanner)"
REGEX = r' \{.*"url":\s*"[^"]*\.(scm|scx|rep|pud|zip|rar)(\?[^"#]*|#[^"#]*)?".*\}$'
PATTERN = re.compile(REGEX)


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


def http_get_streamed(url: str) -> requests.Response:
    retry_strategy = Retry(
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    header = {
        "user-agent": CUSTOM_USER_AGENT
    }
    response = session.get(url, headers=header, timeout=(5, None), stream=True)
    response.raise_for_status()

    return response


def read_index_file(idx_line: str, position: int, output_file: str) -> dict[str, int]:
    idx_line = idx_line.strip()
    if not idx_line:
        return

    r = http_get_streamed(COMMON_CRAWL_S3_BASE_URL + idx_line)
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


def get_indices(input_file: str, output_file: str, resume_url: str | None) -> None:
    # clear output
    if not resume_url:
        open(output_file, "w", encoding="utf-8").close()

    indices = None
    with open(input_file, "r", encoding="utf-8") as f:
        indices = f.readlines()

    with tqdm(total=len(indices), desc="Total", unit="", position=0, leave=True) as progress_bar:
        for i, item in enumerate(indices):
            item = item.strip()
            if resume_url and resume_url != item:
                continue

            resume_url = None

            read_index_file(item, i + 1, output_file)
            progress_bar.update(1)


def get_crawl_index_file(crawl_name: str) -> str:
    url = f"{COMMON_CRAWL_S3_BASE_URL}crawl-data/{crawl_name}/cc-index.paths.gz"
    index_filename = f"{crawl_name}-cc-index.paths"

    # Don't redownload
    if os.path.isfile(index_filename):
        return index_filename

    response = http_get_streamed(url)

    result_list = []
    with gzip.GzipFile(fileobj=response.raw) as gz, io.TextIOWrapper(gz, encoding="utf-8") as reader:
        result_list = [line for line in reader if line.strip().endswith(".gz")]

    if not result_list:
        raise RuntimeError(f"Failed to obtain items from {url}")

    with open(index_filename, "w", encoding="utf-8") as out:
        out.writelines(result_list)

    return index_filename


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Retrieve the indices for a crawl (filenames and archive locations) and filters it to target specific resources.")
    parser.add_argument("crawl_name", help="Name of the crawl (i.e. CC-MAIN-2014-35)")
    parser.add_argument("--resume_url", help="URL to resume at, leave blank to do full retrieval")
    args = parser.parse_args()

    input_index_file = get_crawl_index_file(args.crawl_name)
    get_indices(input_index_file, f"{args.crawl_name}.jsonl", args.resume_url)
    print("\nProcessing complete.")
