#!/usr/bin/env python3

"""
Firmware Anomaly Explainer
Analyzes firmware dump logs, binwalk data, and entropy analysis to generate natural language explanations of detected anomalies.
Part of the Satellite Defense Toolkit - Forensics Suite.
"""

import os
import json
import hashlib
import subprocess
from datetime import datetime
from difflib import unified_diff

# Input files
FIRMWARE_DUMP_PATH = "dumps/latest_firmware_dump.bin"
BINWALK_LOG_PATH = "analysis/binwalk_results.json"
ENTROPY_ANALYSIS_PATH = "analysis/entropy_report.json"
OUTPUT_REPORT_PATH = "results/firmware_anomaly_explained.json"

# Anomaly scoring thresholds
ENTROPY_THRESHOLD = 7.8  # typically above this is compressed/encrypted
UNUSUAL_SECTION_NAMES = [".__badcode", ".hidden", ".patch", ".mod", ".hack", ".nuclear"]

def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def hash_firmware(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def explain_anomalies(binwalk_data, entropy_data):
    explanations = []

    for section in binwalk_data.get("extracted_sections", []):
        name = section.get("name", "")
        offset = section.get("offset", "unknown")
        if name in UNUSUAL_SECTION_NAMES:
            explanations.append({
                "type": "suspicious_section",
                "section": name,
                "offset": offset,
                "explanation": f"Suspicious section name '{name}' found at offset {offset}, possibly injected code or patch."
            })

    for region in entropy_data.get("regions", []):
        entropy = region.get("entropy", 0)
        start = region.get("start", 0)
        end = region.get("end", 0)
        if entropy > ENTROPY_THRESHOLD:
            explanations.append({
                "type": "high_entropy_region",
                "start": start,
                "end": end,
                "entropy": entropy,
                "explanation": f"Region from offset {start} to {end} has high entropy ({entropy:.2f}) — possible encryption or packed code."
            })

    return explanations

def generate_report(explanations, firmware_hash):
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "firmware_hash": firmware_hash,
        "explanation_count": len(explanations),
        "explanations": explanations
    }
    os.makedirs(os.path.dirname(OUTPUT_REPORT_PATH), exist_ok=True)
    with open(OUTPUT_REPORT_PATH, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Firmware anomaly explanation report saved to {OUTPUT_REPORT_PATH}")

def main():
    print("[*] Starting Firmware Anomaly Explainer...")
    
    if not os.path.exists(FIRMWARE_DUMP_PATH):
        print(f"[!] Firmware dump not found at {FIRMWARE_DUMP_PATH}")
        return

    if not os.path.exists(BINWALK_LOG_PATH) or not os.path.exists(ENTROPY_ANALYSIS_PATH):
        print(f"[!] Required analysis files missing.")
        return

    firmware_hash = hash_firmware(FIRMWARE_DUMP_PATH)
    binwalk_data = load_json(BINWALK_LOG_PATH)
    entropy_data = load_json(ENTROPY_ANALYSIS_PATH)

    explanations = explain_anomalies(binwalk_data, entropy_data)
    generate_report(explanations, firmware_hash)

if __name__ == "__main__":
    main()
