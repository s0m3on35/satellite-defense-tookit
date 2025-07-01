# modules/intel/zero_day_mapper.py
import requests
import argparse
import re
import json

GITHUB_SEARCH_URL = "https://api.github.com/search/code?q={query}+in:file+language:Python"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={term}"

def search_github(query):
    print(f"[+] Searching GitHub for: {query}")
    headers = {"Accept": "application/vnd.github+json"}
    response = requests.get(GITHUB_SEARCH_URL.format(query=query), headers=headers)
    results = response.json().get("items", [])
    return [r['html_url'] for r in results]

def search_nvd(term):
    print(f"[+] Searching NVD for: {term}")
    r = requests.get(NVD_API_URL.format(term=term))
    cves = r.json().get("vulnerabilities", [])
    return [cve['cve']['id'] for cve in cves]

def extract_strings(firmware_path):
    with open(firmware_path, 'rb') as f:
        data = f.read()
    strings = re.findall(b"[a-zA-Z0-9_/.-]{6,}", data)
    return list(set([s.decode(errors='ignore') for s in strings]))

def analyze_firmware(firmware_path):
    strings = extract_strings(firmware_path)
    mapped = {}
    for s in strings:
        cves = search_nvd(s)
        gh = search_github(s)
        if cves or gh:
            mapped[s] = {"cves": cves, "github": gh}
    return mapped

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", required=True, help="Path to firmware file")
    parser.add_argument("--out", default="results/zero_day_mapping.json", help="Output file")
    args = parser.parse_args()

    results = analyze_firmware(args.firmware)
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to {args.out}")
