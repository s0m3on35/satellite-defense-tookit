import argparse
import json
import os
import requests
from datetime import datetime

LOG_DIR = "results"
INPUT_PATH = "results/yara_matches.json"
CVE_API_URL = "https://cve.circl.lu/api/search/"

os.makedirs(LOG_DIR, exist_ok=True)

def query_cve(term):
    try:
        response = requests.get(f"{CVE_API_URL}{term}")
        if response.status_code == 200:
            return response.json().get("data", [])
        else:
            return []
    except Exception:
        return []

def extract_terms(matches):
    terms = set()
    for m in matches:
        desc = m.get("meta", {}).get("description", "")
        if desc:
            for word in desc.split():
                if len(word) > 4:
                    terms.add(word.lower())
    return list(terms)

def save_results(results, firmware_path):
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    out_file = os.path.join(LOG_DIR, f"firmware_cve_map_{ts}.json")
    report = {
        "firmware": firmware_path,
        "timestamp": ts,
        "cve_hits": results
    }
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] CVE mapping report saved to {out_file}")

def main():
    parser = argparse.ArgumentParser(description="Map YARA firmware indicators to known CVEs")
    parser.add_argument("--firmware", required=True, help="Path to scanned firmware")
    args = parser.parse_args()

    if not os.path.exists(INPUT_PATH):
        print(f"[!] Match data not found: {INPUT_PATH}")
        return

    with open(INPUT_PATH, "r") as f:
        matches = json.load(f)

    terms = extract_terms(matches)
    results = []

    for term in terms:
        cves = query_cve(term)
        for cve in cves:
            results.append({
                "keyword": term,
                "id": cve.get("id"),
                "summary": cve.get("summary"),
                "cvss": cve.get("cvss"),
                "published": cve.get("Published")
            })

    save_results(results, args.firmware)

if __name__ == "__main__":
    main()
