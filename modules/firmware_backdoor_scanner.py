# modules/firmware_backdoor_scanner.py

import os
import json
import hashlib
import argparse
from datetime import datetime

AGENT_ID = "firmware_backdoor_scanner"
ALERT_FILE = "webgui/alerts.json"
DASHBOARD_AGENTS = "webgui/agents.json"
KNOWN_PATTERNS_FILE = "config/backdoor_patterns.json"
RESULTS_DIR = "results"
MITRE_MAPPING_FILE = "config/mitre_map.json"

def log(msg):
    print(f"[SCANNER] {msg}")

def calculate_hash(filepath, algo="sha256"):
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def load_patterns():
    with open(KNOWN_PATTERNS_FILE, "r") as f:
        return json.load(f)

def load_mitre_map():
    if os.path.exists(MITRE_MAPPING_FILE):
        with open(MITRE_MAPPING_FILE, "r") as f:
            return json.load(f)
    return {}

def scan_file(firmware_path, patterns, mitre_map):
    matches = []
    with open(firmware_path, "rb") as f:
        data = f.read()
        for sig in patterns:
            if sig["type"] == "hex" and bytes.fromhex(sig["value"]) in data:
                match = {
                    "timestamp": datetime.now().isoformat(),
                    "pattern_name": sig["name"],
                    "severity": sig.get("severity", "medium"),
                    "mitre_techniques": mitre_map.get(sig["name"], []),
                    "offset": data.find(bytes.fromhex(sig["value"]))
                }
                matches.append(match)
    return matches

def push_alert(match):
    alert = {
        "agent": AGENT_ID,
        "alert": f"Firmware backdoor pattern: {match['pattern_name']}",
        "type": "firmware",
        "severity": match['severity'],
        "mitre": match["mitre_techniques"],
        "timestamp": match["timestamp"]
    }
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def update_agent_inventory(firmware_path):
    agent_entry = {
        "agent_id": AGENT_ID,
        "last_scan": datetime.now().isoformat(),
        "firmware": os.path.basename(firmware_path)
    }
    os.makedirs(os.path.dirname(DASHBOARD_AGENTS), exist_ok=True)
    if os.path.exists(DASHBOARD_AGENTS):
        with open(DASHBOARD_AGENTS, "r") as f:
            agents = json.load(f)
    else:
        agents = []
    agents = [a for a in agents if a["agent_id"] != AGENT_ID]
    agents.append(agent_entry)
    with open(DASHBOARD_AGENTS, "w") as f:
        json.dump(agents, f, indent=2)

def export_results(matches):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, "firmware_backdoor_matches.json")
    with open(output_path, "w") as f:
        json.dump(matches, f, indent=4)
    log(f"Results saved to {output_path}")

def main(args):
    log("Scanning firmware for backdoor patterns")
    patterns = load_patterns()
    mitre_map = load_mitre_map()
    matches = scan_file(args.firmware, patterns, mitre_map)

    for match in matches:
        push_alert(match)

    update_agent_inventory(args.firmware)
    export_results(matches)

    if not matches:
        log("No backdoor patterns found.")
    else:
        log(f"{len(matches)} suspicious patterns found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Backdoor Scanner")
    parser.add_argument("--firmware", default="test_firmware.bin", help="Firmware binary to scan")
    args = parser.parse_args()
    main(args)
