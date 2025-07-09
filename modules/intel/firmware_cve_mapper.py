#!/usr/bin/env python3
# modules/intel/firmware_cve_mapper.py

import os
import re
import json
import time
import argparse
import requests
from datetime import datetime
from uuid import uuid4

CVE_RESULTS = "results/firmware_cve_matches.json"
STIX_RESULTS = "results/firmware_cve_bundle.json"
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_signatures(firmware_path):
    with open(firmware_path, "rb") as f:
        data = f.read().decode(errors="ignore")
    pattern = re.compile(r"(OpenSSL|BusyBox|Linux kernel|uClibc|libc|libssl)[\s:/\-]*v?[\d\.]+[a-z]?", re.IGNORECASE)
    matches = list(set(pattern.findall(data)))
    return matches

def query_cve_api(keyword, retries=3):
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    for _ in range(retries):
        try:
            res = requests.get(CVE_API, params=params, timeout=15)
            if res.status_code == 200:
                return res.json().get("vulnerabilities", [])
        except:
            time.sleep(2)
    return []

def generate_stix_bundle(cve_matches):
    objects = []
    for item in cve_matches:
        cve_id = item["cve_id"]
        objects.append({
            "type": "vulnerability",
            "id": f"vulnerability--{uuid4()}",
            "name": cve_id,
            "description": item.get("description", ""),
            "created": datetime.utcnow().isoformat() + "Z",
            "external_references": [{
                "source_name": "nvd",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }]
        })
        objects.append({
            "type": "observed-data",
            "id": f"observed-data--{uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "first_observed": item["timestamp"],
            "last_observed": item["timestamp"],
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "file",
                    "name": item["firmware"],
                    "extensions": {
                        "signature": item["signature"]
                    }
                }
            }
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "spec_version": "2.1",
        "objects": objects
    }
    with open(STIX_RESULTS, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"[✓] STIX bundle exported: {STIX_RESULTS}")

def analyze_firmware(fw_path, verbose=False):
    os.makedirs("results", exist_ok=True)
    signatures = extract_signatures(fw_path)
    matches = []

    for sig in signatures:
        if verbose:
            print(f"[•] Querying for: {sig}")
        cves = query_cve_api(sig)
        for item in cves:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            description = cve.get("descriptions", [{}])[0].get("value", "")
            severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "")
            match = {
                "firmware": os.path.basename(fw_path),
                "signature": sig,
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            matches.append(match)
            if verbose:
                print(f"  -> {cve_id} | {severity} | {description[:60]}...")

    with open(CVE_RESULTS, "w") as f:
        json.dump(matches, f, indent=2)
    print(f"[✓] CVE results saved: {CVE_RESULTS}")
    return matches

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", required=True, help="Path to firmware binary")
    parser.add_argument("--stix", action="store_true", help="Export STIX 2.1 bundle")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if not os.path.exists(args.firmware):
        print("[!] Firmware file not found.")
        return

    matches = analyze_firmware(args.firmware, verbose=args.verbose)
    if args.stix and matches:
        generate_stix_bundle(matches)

if __name__ == "__main__":
    main()
