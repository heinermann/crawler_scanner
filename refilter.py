"""Re-filters indices with updated rules"""
import os
import json

from ignore import should_ignore_site


def should_ignore(line: str) -> bool:
    try:
        data = json.loads(line)
    except Exception as e:
        print(f"FAILED JSON READ: {e}\nContent: {line}")
        return True

    return should_ignore_site(data.get("url"))


def reapply(filename):
    os.rename(filename, filename + ".bak")

    with open(filename + ".bak", "r", encoding="utf-8") as f, open(filename, "w", encoding="utf-8") as out:
        for line in f:
            if not should_ignore(line):
                out.write(line)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Reapplies filters to indices from a crawl.")
    parser.add_argument("input_file", help="Path to the input file (e.g., 2008.jsonl)")
    args = parser.parse_args()

    reapply(args.input_file)
    print("\nProcessing complete.")
