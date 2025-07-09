#!/usr/bin/env python3
# modules/analysis/elf_section_analyzer.py

import argparse
import json
import os
from pathlib import Path
from collections import defaultdict
from elftools.elf.elffile import ELFFile

SUSPICIOUS_SECTIONS = [
    ".note",
    ".init_array",
    ".fini_array",
    ".modprobe",
    ".text.unlikely",
    ".data.rel.ro",
    ".bss.hidden",
    ".got.plt",
    ".plt.sec"
]

def analyze_elf(elf_path):
    results = defaultdict(list)
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)

        if not elf.has_dwarf_info():
            results["warnings"].append("No DWARF debug info present (possible stripped binary)")

        for section in elf.iter_sections():
            name = section.name
            size = section['sh_size']
            addr = section['sh_addr']
            flags = section['sh_flags']
            entropy = calc_entropy(section.data()) if section['sh_size'] > 0 else 0

            entry = {
                "name": name,
                "address": hex(addr),
                "size": size,
                "flags": str(flags),
                "entropy": round(entropy, 4),
                "suspicious": name in SUSPICIOUS_SECTIONS or size == 0
            }
            results["sections"].append(entry)

            if entry["suspicious"]:
                results["alerts"].append(f"Suspicious section: {name} @ {hex(addr)}")

    return results

def calc_entropy(data):
    if not data:
        return 0.0
    from math import log2
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    probs = [f / len(data) for f in freq if f > 0]
    return -sum(p * log2(p) for p in probs)

def save_report(results, output_path):
    with open(output_path, 'w') as out:
        json.dump(results, out, indent=2)
    print(f"[+] ELF section analysis saved to: {output_path}")
    if results.get("alerts"):
        print("[!] Suspicious sections detected. Review the report carefully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ELF Section Analyzer with Entropy & Anomaly Detection")
    parser.add_argument("-f", "--file", required=True, help="Path to ELF firmware binary")
    parser.add_argument("-o", "--output", required=True, help="Output JSON report path")
    args = parser.parse_args()

    elf_results = analyze_elf(args.file)
    save_report(elf_results, args.output)
