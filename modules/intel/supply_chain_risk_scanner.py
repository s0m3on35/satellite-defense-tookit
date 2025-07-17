#!/usr/bin/env python3
# File: modules/intel/supply_chain_risk_scanner.py

import os
import json
import re
from datetime import datetime

INPUT_METADATA_FILE = "logs/firmware_metadata.json"
BLOCKLIST_FILE = "config/high_risk_suppliers.json"
OUTPUT_FILE = "results/intel/supply_chain_risks.json"

def load_metadata():
    if not os.path.exists(INPUT_METADATA_FILE):
        print(f"[!] Firmware metadata not found: {INPUT_METADATA_FILE}")
        return {}
    with open(INPUT_METADATA_FILE) as f:
        return json.load(f)

def load_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        return {"vendors": [], "regions": []}
    with open(BLOCKLIST_FILE) as f:
        return json.load(f)

def analyze(metadata, blocklist):
    findings = []
    for field in ["vendor", "manufacturer", "origin_country", "firmware_url", "chipset"]:
        val = metadata.get(field, "").lower()
        for vendor in blocklist.get("vendors", []):
            if vendor.lower() in val:
                findings.append({"field": field, "match": vendor})
        for region in blocklist.get("regions", []):
            if region.lower() in val:
                findings.append({"field": field, "match": region})
    return findings

def save_results(results):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    output = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "supply_chain_findings": results
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Supply chain analysis saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    print("[*] Scanning firmware metadata for supply-chain risks...")
    meta = load_metadata()
    block = load_blocklist()
    results = analyze(meta, block)
    save_results(results)
