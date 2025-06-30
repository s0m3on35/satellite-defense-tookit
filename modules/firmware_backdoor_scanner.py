import os
import json
import argparse
import hashlib
import logging
import re
import yaml
from datetime import datetime

AGENT_ID = "firmware_backdoor_scanner"
ALERT_FILE = "webgui/alerts.json"
FEED_FILE = "webgui/live_feed.jsonl"
BACKDOOR_SIGS = "config/firmware_backdoor_signatures.yaml"
KILLCHAIN_FILE = "killchain.json"
MITRE_FILE = "results/mitre_matrix.json"

def setup_logging(log_path):
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def load_signatures():
    with open(BACKDOOR_SIGS, "r") as f:
        return yaml.safe_load(f)

def compute_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def scan_firmware(path, signatures):
    hits = []
    with open(path, 'rb') as f:
        data = f.read()
        for sig in signatures.get("byte_patterns", []):
            pattern = bytes.fromhex(sig)
            if pattern in data:
                hits.append(f"HEX:{sig}")
        text = data.decode(errors="ignore")
        for keyword in signatures.get("strings", []):
            if re.search(keyword, text):
                hits.append(f"STR:{keyword}")
    return hits

def alert(path, matches):
    timestamp = datetime.utcnow().isoformat()
    alert_obj = {
        "timestamp": timestamp,
        "agent": AGENT_ID,
        "alert": "Firmware backdoor signature matched",
        "matches": matches,
        "file": path,
        "mitre_id": "T1543.003",
        "kill_chain_phase": "Persistence"
    }

    os.makedirs("results", exist_ok=True)
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert_obj) + "\n")

    with open(FEED_FILE, "a") as f:
        f.write(json.dumps(alert_obj) + "\n")

    with open(KILLCHAIN_FILE, "a") as f:
        f.write(json.dumps({
            "timestamp": timestamp,
            "phase": "Persistence - Backdoor Found",
            "details": alert_obj
        }) + "\n")

    with open(MITRE_FILE, "w") as f:
        json.dump({"T1543.003": "Firmware persistence backdoor"}, f, indent=2)

def main(args):
    setup_logging(args.log)
    sigs = load_signatures()
    for fname in os.listdir(args.fwdir):
        if fname.endswith(".bin") or fname.endswith(".img"):
            path = os.path.join(args.fwdir, fname)
            matches = scan_firmware(path, sigs)
            if matches:
                alert(path, matches)
                logging.warning(f"Backdoor detected in {fname}")
            else:
                logging.info(f"No issues in {fname}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Backdoor Pattern Matcher")
    parser.add_argument("--fwdir", default="firmware_samples", help="Firmware sample directory")
    parser.add_argument("--log", default="logs/backdoor_scan.log", help="Log file path")
    args = parser.parse_args()
    main(args)
