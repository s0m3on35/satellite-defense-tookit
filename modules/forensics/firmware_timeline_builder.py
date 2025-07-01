import os
import json
import argparse
import hashlib
import datetime
from collections import defaultdict

RESULTS_DIR = "results"
TIMELINE_JSON = os.path.join(RESULTS_DIR, "firmware_timeline.json")
TIMELINE_TXT = os.path.join(RESULTS_DIR, "firmware_timeline.txt")

os.makedirs(RESULTS_DIR, exist_ok=True)

def calculate_hash(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def scan_firmware_dir(firmware_dir):
    timeline = defaultdict(list)
    for root, _, files in os.walk(firmware_dir):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                stat = os.stat(full_path)
                timestamp = datetime.datetime.utcfromtimestamp(stat.st_mtime).isoformat()
                hash_val = calculate_hash(full_path)
                entry = {
                    "file": os.path.relpath(full_path, firmware_dir),
                    "hash": hash_val,
                    "size": stat.st_size,
                    "modified": timestamp
                }
                timeline[timestamp].append(entry)
            except Exception:
                continue
    return timeline

def save_timeline_json(timeline):
    with open(TIMELINE_JSON, "w") as f:
        json.dump(timeline, f, indent=2)

def save_timeline_txt(timeline):
    with open(TIMELINE_TXT, "w") as f:
        for ts in sorted(timeline):
            f.write(f"[ {ts} ]\n")
            for entry in timeline[ts]:
                f.write(f"  - {entry['file']} | {entry['hash'][:12]} | {entry['size']} bytes\n")
            f.write("\n")

def main():
    parser = argparse.ArgumentParser(description="Firmware Timeline Builder")
    parser.add_argument("--dir", required=True, help="Path to unpacked firmware directory")
    args = parser.parse_args()

    print(f"[*] Scanning firmware directory: {args.dir}")
    timeline = scan_firmware_dir(args.dir)

    print("[*] Writing timeline to JSON and TXT...")
    save_timeline_json(timeline)
    save_timeline_txt(timeline)

    print(f"[✓] Firmware timeline saved to: {TIMELINE_JSON} and {TIMELINE_TXT}")

if __name__ == "__main__":
    main()
