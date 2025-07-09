#!/usr/bin/env python3
# modules/analysis/binary_diff_engine.py

import argparse
import hashlib
import json
from pathlib import Path

CHUNK_SIZE = 4096

def sha256sum(data):
    return hashlib.sha256(data).hexdigest()

def diff_firmwares(base_path, new_path, output_path):
    with open(base_path, 'rb') as f1, open(new_path, 'rb') as f2:
        base_data = f1.read()
        new_data = f2.read()

    report = {
        "base_file": str(base_path),
        "new_file": str(new_path),
        "diff_chunks": []
    }

    max_len = max(len(base_data), len(new_data))
    chunk_index = 0

    for offset in range(0, max_len, CHUNK_SIZE):
        base_chunk = base_data[offset:offset+CHUNK_SIZE]
        new_chunk = new_data[offset:offset+CHUNK_SIZE]

        if base_chunk != new_chunk:
            entry = {
                "chunk": chunk_index,
                "offset": hex(offset),
                "base_sha256": sha256sum(base_chunk),
                "new_sha256": sha256sum(new_chunk),
                "size_changed": len(base_chunk) != len(new_chunk),
                "byte_diff_count": sum(a != b for a, b in zip(base_chunk, new_chunk))
            }
            report["diff_chunks"].append(entry)
        chunk_index += 1

    with open(output_path, 'w') as out:
        json.dump(report, out, indent=2)

    print(f"[+] Diff report saved to: {output_path}")
    print(f"[+] Total differing chunks: {len(report['diff_chunks'])}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Military-Grade Binary Diff Engine for Firmware")
    parser.add_argument("-b", "--base", required=True, help="Original/base firmware image")
    parser.add_argument("-n", "--new", required=True, help="New or modified firmware image")
    parser.add_argument("-o", "--output", required=True, help="Output JSON diff report")
    args = parser.parse_args()

    diff_firmwares(Path(args.base), Path(args.new), Path(args.output))
