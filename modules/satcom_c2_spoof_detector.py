import os
import time
import json
import yaml
import logging
import argparse
from datetime import datetime
from scapy.all import rdpcap, Raw
from base64 import b64encode

AGENT_ID = "satcom_c2_detector"
ALERT_FILE = "webgui/alerts.json"
DASHBOARD_FEED = "webgui/live_feed.jsonl"
PCAP_DIR = "pcaps/"
SIGNATURES_FILE = "config/c2_signatures.yaml"
KILLCHAIN_FILE = "killchain.json"
MITRE_MAP_FILE = "results/mitre_matrix.json"

def setup_logging(log_path):
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def load_signatures(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def alert(trigger, raw_data):
    timestamp = datetime.utcnow().isoformat()
    payload_b64 = b64encode(raw_data).decode()

    alert_obj = {
        "timestamp": timestamp,
        "agent": AGENT_ID,
        "alert": f"C2 pattern detected: {trigger}",
        "type": "satellite_c2",
        "mitre_id": "T1071.001",
        "kill_chain_phase": "Command and Control",
        "payload": payload_b64
    }

    os.makedirs("results", exist_ok=True)
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert_obj) + "\n")

    with open(DASHBOARD_FEED, "a") as f:
        f.write(json.dumps(alert_obj) + "\n")

    with open(KILLCHAIN_FILE, "a") as f:
        f.write(json.dumps({
            "timestamp": timestamp,
            "phase": "C2 Detection",
            "details": alert_obj
        }) + "\n")

    with open(MITRE_MAP_FILE, "w") as f:
        json.dump({"T1071.001": "Satellite C2 detected"}, f, indent=2)

def scan_pcap(pcap_path, signatures):
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if Raw in pkt:
            payload = pkt[Raw].load
            for sig in signatures:
                if sig.encode() in payload:
                    alert(sig, payload)
                    break

def main(args):
    setup_logging(args.log)
    signatures = load_signatures(SIGNATURES_FILE)

    logging.info(f"Starting C2 detection in {PCAP_DIR}")
    for fname in os.listdir(PCAP_DIR):
        if fname.endswith(".pcap"):
            scan_pcap(os.path.join(PCAP_DIR, fname), signatures)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Satellite C2 Trigger & Spoofing Detector")
    parser.add_argument("--log", default="logs/satcom_detector.log", help="Log file path")
    args = parser.parse_args()
    main(args)
