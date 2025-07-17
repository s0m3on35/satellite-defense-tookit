#!/usr/bin/env python3
# File: modules/intel/anomaly_signature_builder.py

import os
import json
from datetime import datetime
from pathlib import Path

INPUT_FILE = "logs/telemetry_anomalies.json"
OUTPUT_FILE = "results/intel/yara_like_anomaly_rules.yar"

def build_yara_rule(entry, index):
    name = entry.get("id", f"anomaly_{index}").replace("-", "_")
    tags = " ".join(entry.get("tags", ["anomaly"]))
    condition = " or ".join([f'uint8[{i}] == {b}' for i, b in enumerate(entry.get("pattern", []))])
    return f"""
rule {name}
{{
    meta:
        timestamp = "{entry.get("timestamp")}"
        source = "{entry.get("source", "telemetry")}"
    strings:
        $pattern = {{{' '.join(f'{b:02x}' for b in entry.get("pattern", []))}}}
    condition:
        $pattern
}}
""".strip()

def convert_to_yara():
    if not Path(INPUT_FILE).exists():
        print(f"[!] Input file not found: {INPUT_FILE}")
        return
    with open(INPUT_FILE, "r") as f:
        data = json.load(f)

    yara_rules = [build_yara_rule(entry, i) for i, entry in enumerate(data.get("anomalies", []))]
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as out:
        out.write("\n\n".join(yara_rules))
    print(f"[+] Generated {len(yara_rules)} YARA-like anomaly rules to {OUTPUT_FILE}")

if __name__ == "__main__":
    print("[*] Building anomaly signature rules from telemetry logs...")
    convert_to_yara()
