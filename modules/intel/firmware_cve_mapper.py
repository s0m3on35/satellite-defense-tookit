import os
import json
import requests
from datetime import datetime

FIRMWARE_DIR = "firmware"
RESULTS_DIR = "results"
CVE_RESULTS = os.path.join(RESULTS_DIR, "firmware_cve_matches.json")
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_version_signatures(firmware_path):
    signatures = []
    with open(firmware_path, "rb") as f:
        data = f.read()
        for line in data.split(b"\n"):
            if b"v" in line.lower() or b"ver" in line.lower():
                line_str = line.decode(errors="ignore").strip()
                if any(char.isdigit() for char in line_str):
                    signatures.append(line_str)
    return list(set(signatures))

def query_cve_api(query):
    params = {"keywordSearch": query, "resultsPerPage": 5}
    try:
        response = requests.get(CVE_API, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get("vulnerabilities", [])
    except Exception:
        return []

def analyze_firmware_for_cves(firmware_path):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    signatures = extract_version_signatures(firmware_path)
    cve_matches = []

    for sig in signatures:
        results = query_cve_api(sig)
        for item in results:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            description = cve.get("descriptions", [{}])[0].get("value", "")
            severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "")
            cve_matches.append({
                "firmware": os.path.basename(firmware_path),
                "signature": sig,
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "timestamp": datetime.utcnow().strftime("%Y%m%d%H%M%S")
            })

    with open(CVE_RESULTS, "w") as f:
        json.dump(cve_matches, f, indent=2)
    print(f"[✓] CVE results saved to: {CVE_RESULTS}")

def main():
    fw_path = input("Firmware path: ").strip()
    if not os.path.exists(fw_path):
        print("[!] Firmware file not found.")
        return
    analyze_firmware_for_cves(fw_path)

if __name__ == "__main__":
    main()
