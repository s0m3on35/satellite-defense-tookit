#!/usr/bin/env python3
# File: modules/intel/ioc_analyzer.py

import re
import os
import json
from glob import glob
from datetime import datetime

INPUT_DIR = "logs/"
OUTPUT_FILE = "results/intel/ioc_analysis_report.json"

IOC_PATTERNS = {
    "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b",
    "url": r"https?://[^\s]+",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b"
}

def scan_files():
    ioc_results = {}
    for file_path in glob(f"{INPUT_DIR}*.*"):
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
            for ioc_type, pattern in IOC_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    ioc_results.setdefault(ioc_type, []).extend(matches)
    for key in ioc_results:
        ioc_results[key] = list(set(ioc_results[key]))
    return ioc_results

def save_report(iocs):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_directory": INPUT_DIR,
        "ioc_summary": iocs
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] IOC analysis saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    print("[*] Running IOC scan...")
    results = scan_files()
    save_report(results)
