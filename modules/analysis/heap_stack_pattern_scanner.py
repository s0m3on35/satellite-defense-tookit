#!/usr/bin/env python3
# modules/analysis/heap_stack_pattern_scanner.py

import argparse
import re
import json
from pathlib import Path
from math import log2
from collections import defaultdict

# Predefined regex-based byte patterns for known shellcode loaders and XOR-based implants
SIGNATURES = {
    "x86_shellcode_stub": rb"\\x31\\xc0\\x50\\x68.{4}\\x89\\xe6\\x50\\x56\\x31\\xdb\\x31\\xc9\\xb1",
    "xor_loader_loop": rb"(\\x8b\\x.*?\\x34\\x.*?\\x30\\x.*?\\xeb)",
    "stack_pivot": rb"(\\x89\\xe5\\x83\\xec.{1})",  # push ebp; mov ebp, esp; sub esp, X
    "encoded_payload": rb"(\\xeb.{1}\\x5e\\x31\\xc9\\xb1)",  # JMP/CALL decoder stub
}

CHUNK_SIZE = 4096

def entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    probs = [f / len(data) for f in freq if f > 0]
    return -sum(p * log2(p) for p in probs)

def scan_memory_regions(file_path):
    with open(file_path, "rb") as f:
        firmware = f.read()

    results = defaultdict(list)
    offset = 0

    for i in range(0, len(firmware), CHUNK_SIZE):
        chunk = firmware[i:i + CHUNK_SIZE]
        e = entropy(chunk)
        if e > 7.2:
            results["high_entropy_regions"].append({
                "offset": hex(i),
                "entropy": round(e, 4)
            })

        for name, pattern in SIGNATURES.items():
            if re.search(pattern, chunk):
                results["pattern_hits"].append({
                    "pattern_name": name,
                    "offset": hex(i),
                    "entropy": round(e, 4)
                })

        offset += CHUNK_SIZE

    return results

def save_report(results, output_path):
    with open(output_path, "w") as out:
        json.dump(results, out, indent=2)
    print(f"[+] Pattern scan report saved to: {output_path}")
    if results["pattern_hits"]:
        print(f"[!] {len(results['pattern_hits'])} suspicious patterns detected.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Heap/Stack Pattern Scanner (Military-Grade)")
    parser.add_argument("-f", "--firmware", required=True, help="Path to raw firmware binary")
    parser.add_argument("-o", "--output", required=True, help="Path to save JSON report")
    args = parser.parse_args()

    results = scan_memory_regions(args.firmware)
    save_report(results, args.output)
