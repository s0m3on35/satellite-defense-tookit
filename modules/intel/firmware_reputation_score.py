#!/usr/bin/env python3
# File: modules/intel/firmware_reputation_score.py

import os
import json
from pathlib import Path

FIRMWARE_REPORTS = [
    "results/intel/ioc_analysis_report.json",
    "results/intel/threat_actor_matches.json",
    "results/intel/firmware_cve_report.json",
    "results/intel/anomaly_score.json"
]

OUTPUT_FILE = "results/intel/firmware_reputation_score.json"

def score_component(file):
    if not os.path.exists(file):
        return 0
    with open(file) as f:
        data = json.load(f)
        if "ioc_summary" in data:
            total = sum(len(v) for v in data["ioc_summary"].values())
            return min(total, 20)
        if "matches" in data:
            return min(len(data["matches"]), 15)
        if "cves" in data:
            return min(len(data["cves"]), 30)
        if "anomaly_score" in data:
            return int(data["anomaly_score"])
    return 0

def calculate_reputation():
    base_score = 100
    deduction = 0
    for file in FIRMWARE_REPORTS:
        deduction += score_component(file)

    final_score = max(0, base_score - deduction)
    return {
        "final_score": final_score,
        "risk_level": "HIGH" if final_score < 50 else "MEDIUM" if final_score < 80 else "LOW"
    }

def save_score(result):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    result["timestamp"] = Path(OUTPUT_FILE).stat().st_mtime
    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Reputation score written to: {OUTPUT_FILE}")

if __name__ == "__main__":
    print("[*] Calculating firmware reputation score...")
    score = calculate_reputation()
    save_score(score)
