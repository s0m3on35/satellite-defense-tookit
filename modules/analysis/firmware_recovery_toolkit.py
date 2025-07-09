#!/usr/bin/env python3
# modules/analysis/firmware_recovery_toolkit.py

import argparse
import hashlib
import os
import shutil
import subprocess
from pathlib import Path
import json

RECOVERED_DIR = "recovered_sections"
RECOVERY_LOG = "recovery_log.json"

KNOWN_MAGIC = {
    b"\x1f\x8b\x08": "gzip",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\x50\x4b\x03\x04": "zip",
    b"\x48\x65\x61\x64": "squashfs",
    b"\x55\xaa": "mbr_boot"
}

def detect_magic(data):
    for magic, label in KNOWN_MAGIC.items():
        if data.startswith(magic):
            return label
    return "unknown"

def extract_chunks(firmware_path, output_dir):
    with open(firmware_path, "rb") as f:
        data = f.read()

    os.makedirs(output_dir, exist_ok=True)
    chunks = []
    offset = 0
    CHUNK_SIZE = 0x10000  # 64 KB

    while offset < len(data):
        chunk = data[offset:offset+CHUNK_SIZE]
        sha256 = hashlib.sha256(chunk).hexdigest()
        label = detect_magic(chunk)
        fname = f"chunk_{offset:08X}_{label}_{sha256[:6]}.bin"
        path = Path(output_dir) / fname
        with open(path, "wb") as out:
            out.write(chunk)

        chunks.append({
            "offset": hex(offset),
            "filename": fname,
            "sha256": sha256,
            "type": label
        })

        offset += CHUNK_SIZE

    return chunks

def sanitize_extracted(output_dir):
    for file in os.listdir(output_dir):
        full_path = os.path.join(output_dir, file)
        if file.endswith(".bin") and "gzip" in file:
            subprocess.run(["gunzip", "-f", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def generate_log(chunks, output_dir):
    report = {
        "total_chunks": len(chunks),
        "recovered": chunks
    }
    with open(Path(output_dir) / RECOVERY_LOG, "w") as f:
        json.dump(report, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Firmware Recovery Toolkit (Military-Grade Partition Rebuilder)")
    parser.add_argument("-f", "--firmware", required=True, help="Path to corrupted or extracted firmware image")
    parser.add_argument("-o", "--output", required=True, help="Output directory for recovered chunks")
    args = parser.parse_args()

    recovered_chunks = extract_chunks(args.firmware, args.output)
    sanitize_extracted(args.output)
    generate_log(recovered_chunks, args.output)

    print(f"[+] Recovery complete. {len(recovered_chunks)} sections extracted.")
    print(f"[+] Output written to: {args.output}/{RECOVERY_LOG}")

if __name__ == "__main__":
    main()
