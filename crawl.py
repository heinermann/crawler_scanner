#!/usr/bin/env python3
import gzip
import hashlib
import io
import json
import os
import time
import zipfile
from datetime import datetime
from urllib.parse import unquote, urlparse

import rarfile
import requests
from pathvalidate import sanitize_filepath
from warcio.archiveiterator import ArchiveIterator


COMMON_CRAWL_S3_BASE_URL = "https://data.commoncrawl.org/"
CUSTOM_USER_AGENT = "Mozilla/5.0 (compatible; CustomDownloader/0.1; +https://github.com/heinermann/crawler_scanner)"
TARGET_EXTENSIONS = [".pud", ".rep", ".scm", ".scx"]
# Map size lowerbound: 240 bytes


class ZIPHAS:
    """Matching states if a potential file is contained in the zip archive"""
    MATCH = 1
    NO_MATCH = 2
    FAILED_INSPECTION = 3


def is_archive_matching(archive_file) -> int:
    """Checks if the archive contains a file which matches one of the target extensions"""
    for member_name in archive_file.namelist():
        ext_lower = os.path.splitext(member_name)[1].lower()
        if ext_lower not in TARGET_EXTENSIONS:
            continue

        print("Found known extension inside archive")

        with archive_file.open(member_name) as f:
            data = f.read(length=8)
            if is_desired_file_header(data):
                return ZIPHAS.MATCH

    return ZIPHAS.NO_MATCH


def check_zip_archive(archive_stream) -> int:
    """Checks a zip archive for contained files"""
    try:
        with zipfile.ZipFile(archive_stream, 'r') as archive_file:
            return is_archive_matching(archive_file)
    except zipfile.BadZipFile:
        print("Failed to inspect ZIP archive (BadZipFile).")
    except Exception as e_archive:
        print(f"Unexpected error inspecting ZIP archive: {e_archive}")
    return ZIPHAS.FAILED_INSPECTION


def check_rar_archive(archive_stream) -> int:
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
    return ZIPHAS.FAILED_INSPECTION


def check_archive_contents(payload_bytes, archive_type) -> int:
    """Checks contents of a ZIP or RAR archive. Returns 'MATCH', 'NO_MATCH', or 'FAILED_INSPECTION'."""
    archive_stream = io.BytesIO(payload_bytes)
    if archive_type == "zip":
        return check_zip_archive(archive_stream)
    elif archive_type == "rar":
        return check_rar_archive(archive_stream)
    return ZIPHAS.FAILED_INSPECTION


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


def should_save_this_record(payload_bytes, original_filename_from_url) -> bool:
    """Checks if this record should be saved or not."""
    archive_inspection_actually_failed = False

    file_ext_original = os.path.splitext(original_filename_from_url)[1].lower()

    if file_ext_original == '.zip':
        archive_status = check_archive_contents(payload_bytes, "zip")
        if archive_status == ZIPHAS.MATCH:
            print("Found ZIP")
            return True
        elif archive_status == ZIPHAS.FAILED_INSPECTION:
            archive_inspection_actually_failed = True
    elif file_ext_original == '.rar':
        archive_status = check_archive_contents(payload_bytes, "rar")
        if archive_status == ZIPHAS.MATCH:
            print("Found RAR")
            return True
        elif archive_status == ZIPHAS.FAILED_INSPECTION:
            archive_inspection_actually_failed = True

    if file_ext_original in TARGET_EXTENSIONS or archive_inspection_actually_failed:
        return is_desired_file_header(payload_bytes)

    return False


def save_file(payload_bytes, parsed_original_url, record, output_dir_base):
    original_filename_from_url = os.path.basename(parsed_original_url.path)
    if not original_filename_from_url:
        original_filename_from_url = sanitize_filepath(parsed_original_url.netloc, "_") + "_index"

    file_ext_original = os.path.splitext(original_filename_from_url)[1].lower()[1:]
    last_modified_date_str = record.rec_headers.get_header("WARC-Date")

    domain_name = sanitize_filepath(parsed_original_url.netloc, "_")
    sanitized_final_filename = unquote(sanitize_filepath(original_filename_from_url, "_"))

    final_save_path = os.path.join(output_dir_base, file_ext_original, domain_name, sanitized_final_filename)
    if os.path.isfile(final_save_path):
        final_save_path = os.path.join(output_dir_base, file_ext_original, domain_name, last_modified_date_str, sanitized_final_filename)

    os.makedirs(os.path.dirname(final_save_path), exist_ok=True)

    with open(final_save_path, 'wb') as f:
        f.write(payload_bytes)

    # set the last modified datetime of the file we just wrote
    filetime = datetime.fromisoformat(last_modified_date_str).timestamp()
    os.utime(final_save_path, (filetime, filetime))

    print(f"Saved payload to: {final_save_path}")


def request_record(target_url: str, offset: int, length: int, original_filename_url: str) -> requests.Response:
    print(f"Processing: {original_filename_url}")

    headers = {
        'Range': f'bytes={offset}-{offset + length - 1}',
        'User-Agent': CUSTOM_USER_AGENT
    }
    response = requests.get(target_url, headers=headers, timeout=(5, None), stream=True)
    response.raise_for_status()
    return response


def download_and_extract_payload(target_url: str, offset: int, length: int, original_filename_url: str, output_dir_base: str) -> None:
    """Downloads a byte range, decompresses, checks conditions, and saves if criteria are met."""
    try:
        response = request_record(target_url, offset, length, original_filename_url)

        for record in ArchiveIterator(response.raw):
            if record.rec_type != 'response' and record.rec_type != 'resource':
                continue

            parsed_original_url = urlparse(original_filename_url)

            original_filename_from_url = os.path.basename(parsed_original_url.path)
            if not original_filename_from_url:
                original_filename_from_url = sanitize_filepath(parsed_original_url.netloc, "_") + "_index"

            should_save: bool = False

            # Do a quick check for known file extensions
            file_ext_original = os.path.splitext(original_filename_from_url)[1].lower()
            if file_ext_original in TARGET_EXTENSIONS:
                # Only need 8 bytes for the check
                payload_bytes = record.content_stream().read(length=8)
                should_save = is_desired_file_header(payload_bytes)

                # It's definitely NOT going to be valid
                if not should_save:
                    continue

                # read the rest of the stream
                payload_bytes += record.content_stream().read()
            elif length < 1 * 1024 * 1024:  # is a zip/rar OR a map file renamed to zip (less than 1MB)
                # TODO do iterative check for zip and rar files too
                payload_bytes = record.content_stream().read()
                should_save = should_save_this_record(payload_bytes, original_filename_from_url)

            if should_save:
                save_file(payload_bytes, parsed_original_url, record, output_dir_base)
                break

    except requests.exceptions.RequestException as e:
        print(f"Error downloading {target_url}: {e}")
    except gzip.BadGzipFile:
        print(f"Error: Downloaded content for {target_url} is not a valid GZip file. Offset/Length might be incorrect or data corrupted.")
    finally:
        time.sleep(0.1)


def process_input_file(filepath: str, output_dir: str) -> None:
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

            if not all([s3_path, offset_str, length_str, original_url_for_naming]):
                continue

            offset = int(offset_str)
            length = int(length_str)

            download_url: str = COMMON_CRAWL_S3_BASE_URL + s3_path
            download_and_extract_payload(download_url, offset, length, original_url_for_naming, output_dir)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Download and extract WARC payloads from a list of URLs and byte ranges based on specific criteria.")
    parser.add_argument("input_file", help="Path to the input file (e.g., 2013-20.txt)")
    parser.add_argument("--output_dir", default="output_payloads", help="Base directory to save extracted payloads (default: output_payloads)")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    process_input_file(args.input_file, args.output_dir)
    print("\nProcessing complete.")
