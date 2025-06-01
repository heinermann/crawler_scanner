#!/usr/bin/env python3
import gzip
import io
import json
import os
import time
import zipfile
from datetime import datetime
from urllib.parse import unquote, urlparse

import rarfile
import requests
from construct import Bytes, Const, ConstError, ConstructError, Int16ul, Int32ul, Struct
from pathvalidate import sanitize_filepath
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from warcio.archiveiterator import ArchiveIterator


COMMON_CRAWL_S3_BASE_URL = "https://data.commoncrawl.org/"
CUSTOM_USER_AGENT = "Mozilla/5.0 (compatible; CustomDownloader/0.1; +https://github.com/heinermann/crawler_scanner)"
TARGET_EXTENSIONS = {".pud", ".rep", ".scm", ".scx"}

# Sometimes maps can have a preview image or doc shipped with it
ALLOWED_EXTENSIONS = {".txt", ".nfo", ".doc", ".jpg", ".png", ".bmp", ".diz", ".ini", ".db", ".rtf", ".trg"}
# Map size lowerbound: 240 bytes

# TODO stream-unzip? https://stream-unzip.docs.trade.gov.uk/

zip_header = Struct(
    "signature" / Const(b"PK\x03\x04"),
    "version" / Int16ul,
    "flags" / Int16ul,
    "compression" / Int16ul,
    "mod_time" / Int16ul,
    "mod_date" / Int16ul,
    "crc32" / Int32ul,
    "compressed_size" / Int32ul,
    "uncompressed_size" / Int32ul,
    "filename_len" / Int16ul,
    "extra_len" / Int16ul,
    "filename" / Bytes(lambda this: this.filename_len),
    "extra" / Bytes(lambda this: this.extra_len),
)


def is_archive_matching(archive_file) -> bool:
    """Checks if the archive contains a file which matches one of the target extensions"""
    for member_name in archive_file.namelist():
        ext_lower = os.path.splitext(member_name)[1].lower()
        if ext_lower not in TARGET_EXTENSIONS:
            continue

        print("Found known extension inside archive")

        with archive_file.open(member_name) as f:
            data = f.read(length=8)
            if is_desired_file_header(data):
                return True

    return False


def check_zip_archive(archive_stream) -> bool:
    """Checks a zip archive for contained files"""
    try:
        with zipfile.ZipFile(archive_stream, 'r') as archive_file:
            return is_archive_matching(archive_file)
    except zipfile.BadZipFile:
        print("Failed to inspect ZIP archive (BadZipFile).")
    except Exception as e_archive:
        print(f"Unexpected error inspecting ZIP archive: {e_archive}")
    return False


def check_rar_archive(archive_stream) -> bool:
    """Checks a rar archive for contained files"""
    try:
        with rarfile.RarFile(archive_stream, 'r') as archive_file:
            return is_archive_matching(archive_file)
    except rarfile.BadRarFile:
        print("Failed to inspect RAR archive (BadRarFile).")
    except rarfile.NotRarFile:
        print("File is not a RAR archive (NotRarFile) though identified as one.")
    except rarfile.NeedFirstVolume:
        print("RAR archive is multi-volume and needs first volume (NeedFirstVolume).")
    except rarfile.RarExecError as e:
        print(f"Unrar tool failed (RarExecError): {e}.")
    except Exception as e_archive:
        print(f"Unexpected error inspecting RAR archive: {e_archive}")
    return False


def check_archive_contents(payload_bytes, archive_type) -> bool:
    """Checks contents of a ZIP or RAR archive. Returns 'MATCH', 'NO_MATCH', or 'FAILED_INSPECTION'."""
    archive_stream = io.BytesIO(payload_bytes)
    if archive_type == ".zip":
        return check_zip_archive(archive_stream)
    elif archive_type == ".rar":
        return check_rar_archive(archive_stream)
    return False


def is_desired_file_header(payload_bytes) -> bool:
    """Checks the contents of the file header for known types."""
    if payload_bytes.startswith(b"MPQ\x1a"):
        print("Found SCM/SCX/MPQ")
        return True
    elif payload_bytes.startswith(b"\xa7\x7e\x7e\x2b\x01\x00\x00\x00"):
        print("Found REP")
        return True
    elif payload_bytes.startswith(b"TYPE\x10\x00\x00\x00"):
        print("Found PUD/CHK")
        return True
    return False


def is_archive_file_header(payload_bytes) -> bool:
    """Checks the contents of the file header for archive file types."""
    if payload_bytes.startswith(b"PK\x03\x04"):
        return True
    elif payload_bytes.startswith(b"Rar!"):
        return True
    return False


def save_file(payload_bytes, parsed_original_url, record, output_dir_base):
    original_filename_from_url = os.path.basename(parsed_original_url.path)
    if not original_filename_from_url:
        original_filename_from_url = sanitize_filepath(parsed_original_url.netloc, "_") + "_index"

    file_ext_original = os.path.splitext(original_filename_from_url)[1].lower()[1:]
    last_modified_date_str = record.rec_headers.get_header("WARC-Date")

    # Convert old time format to iso string
    if last_modified_date_str is None:
        last_modified_date_str = record.rec_headers.get_header("archive-date")
        dt = datetime.strptime(last_modified_date_str, "%Y%m%d%H%M%S")
        last_modified_date_str = dt.isoformat()

    sanitized_final_filename = unquote(original_filename_from_url)

    final_save_path = os.path.join(output_dir_base, file_ext_original, parsed_original_url.netloc, sanitized_final_filename)
    if os.path.isfile(final_save_path):
        final_save_path = os.path.join(output_dir_base, file_ext_original, parsed_original_url.netloc, last_modified_date_str, sanitized_final_filename)

    final_save_path = sanitize_filepath(final_save_path, "_")
    os.makedirs(os.path.dirname(final_save_path), exist_ok=True)

    with open(final_save_path, 'wb') as f:
        f.write(payload_bytes)

    # set the last modified datetime of the file we just wrote
    filetime = datetime.fromisoformat(last_modified_date_str).timestamp()
    os.utime(final_save_path, (filetime, filetime))

    print(f"Saved payload to: {final_save_path}")


def request_record(target_url: str, offset: int, length: int, original_filename_url: str) -> requests.Response:
    print(f"Processing: {original_filename_url}")

    retry_strategy = Retry(
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    headers = {
        'Range': f'bytes={offset}-{offset + length - 1}',
        'User-Agent': CUSTOM_USER_AGENT
    }
    response = session.get(target_url, headers=headers, timeout=(5, None), stream=True)
    response.raise_for_status()
    return response


def process_zip_file_preview(initial_bytes):
    num_read = 0
    try:
        byte_stream = io.BytesIO(initial_bytes)

        while True:
            hdr = zip_header.parse_stream(byte_stream)
            num_read += 1

            # assuming a directory, go to the next entry
            if hdr.compressed_size == 0:
                continue

            extension = str(os.path.splitext(hdr.filename)[1], encoding="utf-8").lower()

            # Possibly a map
            if extension in TARGET_EXTENSIONS:
                print(f"Has target extension: {extension}")
                return True

            # definitely not a map
            if extension not in ALLOWED_EXTENSIONS:
                print(f"Short circuiting on extension: {extension}")
                return False

            # unknowable and not parsing other structs to find out right now
            return True

    except ConstError:
        print("Zip header doesn't match, skipping")
        return False
    except ConstructError as e:
        print(f"Zip parsing threw error after reading {num_read} entries: {type(e).__name__} {e}")
    except Exception as e:
        print(f"Unhandled exception in process_zip_file after reading {num_read} entries: {e}")

    # Be safe and assume we just hit the end of preview with an exception
    return True


def download_and_extract_payload(target_url: str, offset: int, length: int, original_filename_url: str, output_dir_base: str) -> None:
    """Downloads a byte range, decompresses, checks conditions, and saves if criteria are met."""
    try:
        while True:
            response = request_record(target_url, offset, length, original_filename_url)
            if response.status_code == 206:
                break

            # rate limited
            if response.status_code == 503:
                time.sleep(0.4)
                continue

            print(f"Unexpected status code: {response.status_code}")
            time.sleep(0.5)

        for record in ArchiveIterator(response.raw):
            if record.rec_type != 'response' and record.rec_type != 'resource':
                time.sleep(0.2)
                continue

            parsed_original_url = urlparse(original_filename_url)

            original_filename_from_url = os.path.basename(parsed_original_url.path)
            if not original_filename_from_url:
                original_filename_from_url = sanitize_filepath(parsed_original_url.netloc, "_") + "_index"

            should_save: bool = False

            # Do a quick check for known file extensions
            file_ext_original = os.path.splitext(original_filename_from_url)[1].lower()

            # Only need 8 bytes for the initial checks
            payload_bytes = record.content_stream().read(length=1024)
            time.sleep(0.1)

            should_save = is_desired_file_header(payload_bytes)
            if should_save:  # is a SCM/SCX/REP/PUD
                # read the rest of the stream and save it
                payload_bytes += record.content_stream().read()
                save_file(payload_bytes, parsed_original_url, record, output_dir_base)
            elif file_ext_original in TARGET_EXTENSIONS:
                # It's definitely NOT going to be valid if the extension is correct but header is wrong
                if not should_save:
                    continue
            elif not is_archive_file_header(payload_bytes):
                # Not a valid archive header
                continue
            elif file_ext_original == ".zip":
                should_save = process_zip_file_preview(payload_bytes)
                if should_save:
                    payload_bytes += record.content_stream().read()
                    should_save = check_archive_contents(payload_bytes, file_ext_original)
                    if should_save:
                        print("found ZIP")
                        save_file(payload_bytes, parsed_original_url, record, output_dir_base)

            elif file_ext_original == ".rar":
                payload_bytes += record.content_stream().read()
                should_save = check_archive_contents(payload_bytes, file_ext_original)
                if should_save:
                    print("found RAR")
                    save_file(payload_bytes, parsed_original_url, record, output_dir_base)

    except requests.exceptions.RequestException as e:
        print(f"Error downloading {target_url}: {e}")
    except gzip.BadGzipFile:
        print(f"Error: Downloaded content for {target_url} is not a valid GZip file. Offset/Length might be incorrect or data corrupted.")
    finally:
        time.sleep(0.2)


def process_input_file(filepath: str, output_dir: str, resume_url: str) -> None:
    """
    Reads the input file line by line, parses the JSON,
    and calls the download function.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)

            s3_path = data.get("filename")
            offset_str = data.get("offset")
            length_str = data.get("length")
            original_url_for_naming = data.get("url")

            if resume_url and resume_url != original_url_for_naming:
                continue

            resume_url = None

            if not all([s3_path, offset_str, length_str, original_url_for_naming]):
                continue

            offset = int(offset_str)
            length = int(length_str)

            download_url: str = COMMON_CRAWL_S3_BASE_URL + s3_path
            download_and_extract_payload(download_url, offset, length, original_url_for_naming, output_dir)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Download and extract WARC payloads from a list of URLs and byte ranges based on specific criteria.")
    parser.add_argument("input_file", help="Path to the input file (e.g., 2013-20.jsonl)")
    parser.add_argument("--output_dir", default="output_payloads", help="Base directory to save extracted payloads (default: output_payloads)")
    parser.add_argument("--resume_url", help="URL to resume at")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    process_input_file(args.input_file, args.output_dir, args.resume_url)
    print("\nProcessing complete.")
