#!/usr/bin/env python3
# modules/forensics/flash_sector_dumper.py

import os
import hashlib
import argparse
import json
import logging
from pathlib import Path
from statistics import mean
from math import log2

SECTOR_SIZE = 4096

def calc_entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    probs = [f / len(data) for f in freq if f > 0]
    return -sum(p * log2(p) for p in probs)

def dump_flash(device, output_dir, report_path):
    os.makedirs(output_dir, exist_ok=True)
    log_path = Path(output_dir) / "dump.log"
    logging.basicConfig(filename=log_path, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    logging.info(f"Starting flash dump from: {device}")
    report = {"device": device, "sectors": []}

    with open(device, 'rb') as f:
        sector_num = 0
        while chunk := f.read(SECTOR_SIZE):
            hash_val = hashlib.sha256(chunk).hexdigest()
            entropy = calc_entropy(chunk)
            sector_file = Path(output_dir) / f"sector_{sector_num:05d}_{hash_val[:8]}.bin"
            with open(sector_file, 'wb') as out:
                out.write(chunk)
            logging.info(f"Sector {sector_num:05d}: SHA256={hash_val} | Entropy={entropy:.4f}")
            report["sectors"].append({
                "index": sector_num,
                "hash": hash_val,
                "entropy": round(entropy, 4),
                "filename": str(sector_file.name)
            })
            sector_num += 1

    with open(report_path, 'w') as rep_out:
        json.dump(report, rep_out, indent=4)
    logging.info(f"Dump completed: {sector_num} sectors written. Report: {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Military-Grade NAND/NOR Flash Sector Dumper")
    parser.add_argument("-d", "--device", required=True, help="Path to raw flash memory device (e.g., /dev/mtd0)")
    parser.add_argument("-o", "--output", required=True, help="Output directory for dumped sectors")
    parser.add_argument("-r", "--report", default="flash_dump_report.json", help="Output JSON report path")
    args = parser.parse_args()

    dump_flash(args.device, args.output, args.report)
