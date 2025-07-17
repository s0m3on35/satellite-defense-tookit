#!/usr/bin/env python3
# File: modules/forensics/firmware_anomaly_explainer.py

import os
import json
import math
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from collections import Counter

FIRMWARE_DIR = "firmware"
REPORT_DIR = "results/firmware_forensics"
STIX_OUTPUT = "results/stix_firmware_anomalies.json"
LOG_FILE = "logs/firmware_anomaly_explainer.log"

Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
Path("logs").mkdir(exist_ok=True)

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {msg}\n")
    print(f"[+] {msg}")

def calculate_entropy(data):
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    probs = [float(count) / length for count in counter.values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    return round(entropy, 4)

def analyze_sections(file_path):
    try:
        output = subprocess.check_output(["readelf", "-S", file_path], text=True)
        suspicious = [line.strip() for line in output.splitlines() if any(x in line for x in [".inject", ".unknown", ".hack"])]
        return suspicious
    except Exception as e:
        log(f"[!] readelf failed: {e}")
        return []

def extract_strings(file_path):
    try:
        output = subprocess.check_output(["strings", file_path], text=True)
        strings = output.splitlines()
        anomalies = [s for s in strings if any(x in s.lower() for x in ["backdoor", "shell", "malware", "/bin/sh", "keylogger", "hax"])]
        return anomalies
    except Exception as e:
        log(f"[!] strings failed: {e}")
        return []

def hash_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    return sha256, data

def generate_report(file_path):
    filename = os.path.basename(file_path)
    sha256, binary_data = hash_file(file_path)
    entropy = calculate_entropy(binary_data)
    section_suspicion = analyze_sections(file_path)
    string_anomalies = extract_strings(file_path)

    result = {
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
        "sha256": sha256,
        "entropy": entropy,
        "suspicious_sections": section_suspicion,
        "anomalous_strings": string_anomalies,
        "summary": {
            "entropy_status": "HIGH" if entropy > 7.5 else "NORMAL",
            "section_anomalies": len(section_suspicion),
            "string_hits": len(string_anomalies),
        }
    }

    out_path = os.path.join(REPORT_DIR, f"{filename}_forensic_report.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    log(f"[+] Report saved: {out_path}")
    export_stix(result)
    return result

def export_stix(report):
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{report['sha256'][:12]}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "file",
                "id": f"file--{report['sha256'][:20]}",
                "hashes": {"SHA-256": report["sha256"]},
                "name": report["filename"],
                "x_detected_entropy": report["entropy"],
                "x_anomalous_strings": report["anomalous_strings"],
                "x_suspicious_sections": report["suspicious_sections"]
            }
        ]
    }
    with open(STIX_OUTPUT, "w") as f:
        json.dump(stix_bundle, f, indent=2)
    log(f"[+] STIX file exported: {STIX_OUTPUT}")

def main():
    log("[*] Starting firmware anomaly explainer...")
    targets = [f for f in os.listdir(FIRMWARE_DIR) if f.endswith(".bin") or f.endswith(".elf")]
    if not targets:
        log("[!] No firmware binaries found.")
        return
    for f in targets:
        path = os.path.join(FIRMWARE_DIR, f)
        report = generate_report(path)
        log(f"[✓] Completed forensic analysis for {f}")

if __name__ == "__main__":
    main()
