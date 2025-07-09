# modules/intel/zero_day_mapper_pro.py
import requests
import argparse
import re
import json
import os
from datetime import datetime
import websockets
import asyncio
import socket

GITHUB_SEARCH_URL = "https://api.github.com/search/code?q={query}+in:file+language:Python"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={term}"
MITRE_PATTERNS = {
    "system\(": "T1059.003",
    "eval\(": "T1059.001",
    "wget": "T1105",
    "curl": "T1105",
    "base64": "T1027",
    "xor": "T1027",
}
WS_URI = "ws://localhost:8765"
OUTPUT_JSON = "results/zero_day_mapping.json"
OUTPUT_HTML = "results/zero_day_mapping.html"
OUTPUT_STIX = "results/stix_zero_day_mapping.json"

def search_github(query):
    headers = {"Accept": "application/vnd.github+json"}
    try:
        response = requests.get(GITHUB_SEARCH_URL.format(query=query), headers=headers, timeout=10)
        results = response.json().get("items", [])
        return [r['html_url'] for r in results]
    except:
        return []

def search_nvd(term):
    try:
        r = requests.get(NVD_API_URL.format(term=term), timeout=10)
        cves = r.json().get("vulnerabilities", [])
        return [cve['cve']['id'] for cve in cves]
    except:
        return []

def extract_strings(firmware_path):
    with open(firmware_path, 'rb') as f:
        data = f.read()
    strings = re.findall(b"[a-zA-Z0-9_:/.-]{6,}", data)
    return list(set([s.decode(errors='ignore') for s in strings]))

def classify_string(s):
    if s.startswith("http") or s.startswith("www."):
        return "url"
    elif "/" in s:
        return "path"
    elif "." in s and s.split(".")[-1].isalpha():
        return "domain"
    else:
        return "raw"

def mitre_map(s):
    for pattern, attck_id in MITRE_PATTERNS.items():
        if re.search(pattern, s, re.IGNORECASE):
            return attck_id
    return None

def generate_html_report(data, path):
    rows = ""
    for s, meta in data.items():
        cves = "<br>".join(meta.get("cves", []))
        gh = "<br>".join(meta.get("github", []))
        mitre = meta.get("mitre", "")
        rows += f"<tr><td>{s}</td><td>{meta.get('type')}</td><td>{cves}</td><td>{gh}</td><td>{mitre}</td></tr>"
    html = f"""<html><head><style>
    table {{border-collapse: collapse; width: 100%; font-family: monospace;}}
    th, td {{border: 1px solid #888; padding: 4px; text-align: left;}}
    th {{background-color: #444; color: #fff;}}
    </style></head>
    <body><h2>Zero-Day Mapping Report</h2>
    <table><tr><th>String</th><th>Type</th><th>CVE Matches</th><th>GitHub Links</th><th>MITRE ATT&CK</th></tr>
    {rows}</table></body></html>"""
    with open(path, "w") as f:
        f.write(html)

async def send_to_dashboard(data):
    try:
        async with websockets.connect(WS_URI) as ws:
            await ws.send(json.dumps({
                "type": "zero_day_report",
                "source": "zero_day_mapper",
                "hostname": socket.gethostname(),
                "timestamp": datetime.utcnow().isoformat(),
                "payload": data
            }))
    except:
        pass

def build_stix_bundle(results):
    bundle = {
        "type": "bundle",
        "id": "bundle--" + datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        "objects": []
    }
    for s, meta in results.items():
        obj = {
            "type": "indicator",
            "id": "indicator--" + str(abs(hash(s)))[:10],
            "name": s,
            "description": f"Possible zero-day indicator from firmware string.",
            "pattern": "[file:name = '{}']".format(s.replace("'", "")),
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "labels": [meta.get("type")] + (["mitre:" + meta["mitre"]] if meta.get("mitre") else [])
        }
        bundle["objects"].append(obj)
    with open(OUTPUT_STIX, "w") as f:
        json.dump(bundle, f, indent=2)

def main(firmware_path):
    os.makedirs("results", exist_ok=True)
    strings = extract_strings(firmware_path)
    mapped = {}

    for s in strings:
        s_type = classify_string(s)
        cves = search_nvd(s)
        gh = search_github(s)
        mitre = mitre_map(s)
        if cves or gh or mitre:
            mapped[s] = {
                "type": s_type,
                "cves": cves,
                "github": gh,
                "mitre": mitre
            }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(mapped, f, indent=2)
    generate_html_report(mapped, OUTPUT_HTML)
    build_stix_bundle(mapped)
    asyncio.run(send_to_dashboard(mapped))
    print(f"[â] JSON saved to: {OUTPUT_JSON}")
    print(f"[â] HTML saved to: {OUTPUT_HTML}")
    print(f"[â] STIX saved to: {OUTPUT_STIX}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", required=True, help="Path to firmware binary")
    args = parser.parse_args()
    main(args.firmware)
