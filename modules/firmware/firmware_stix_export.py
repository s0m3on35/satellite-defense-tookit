# firmware_stix_export.py (Phase 7+)
# Firmware Anomaly Detection, STIX/TAXII Export, Dashboard Upload, Killchain Mapping

import os
import json
import hashlib
import logging
import argparse
from datetime import datetime
from stix2 import Indicator, ObservedData, Bundle, File
from taxii2client.v20 import Server
import uuid
import requests

# === Setup ===
def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def hash_firmware(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def detect_firmware_anomalies(file_path):
    hash_val = hash_firmware(file_path)
    logging.info(f"Firmware hash: {hash_val}")
    suspicious_patterns = ["telnet", "busybox", "dropbear", "reverse shell"]
    with open(file_path, 'rb') as f:
        content = f.read().decode(errors='ignore')
        for pattern in suspicious_patterns:
            if pattern in content:
                logging.warning(f"Suspicious string detected: {pattern}")
                return True, pattern, hash_val
    return False, None, hash_val

def map_killchain_stage(pattern):
    mapping = {
        "telnet": "Initial Access",
        "busybox": "Execution",
        "dropbear": "Persistence",
        "reverse shell": "Command and Control"
    }
    return mapping.get(pattern, "Unknown")

def create_stix_bundle(pattern, hash_val, filename, killchain_stage):
    file_obs = File(
        name=filename,
        hashes={"SHA-256": hash_val},
        defanged=False
    )
    indicator = Indicator(
        id=f"indicator--{uuid.uuid4()}",
        name="Firmware Backdoor Pattern",
        pattern_type="stix",
        pattern=f"[file:name = '{filename}' AND file:hashes.'SHA-256' = '{hash_val}']",
        valid_from=datetime.utcnow(),
        kill_chain_phases=[{
            "kill_chain_name": "mitre-attack",
            "phase_name": killchain_stage
        }]
    )
    obs_data = ObservedData(
        id=f"observed-data--{uuid.uuid4()}",
        first_observed=datetime.utcnow(),
        last_observed=datetime.utcnow(),
        number_observed=1,
        objects={"0": file_obs}
    )
    bundle = Bundle(objects=[indicator, obs_data])
    return bundle

def save_bundle(bundle, path):
    with open(path, 'w') as f:
        f.write(bundle.serialize(pretty=True))
    logging.info(f"STIX bundle saved to {path}")

def send_to_dashboard(bundle_path):
    url = "http://localhost:8080/api/alerts"
    with open(bundle_path, 'r') as f:
        payload = json.load(f)
    try:
        r = requests.post(url, json=payload)
        if r.ok:
            logging.info("Alert sent to dashboard successfully.")
        else:
            logging.error(f"Dashboard rejected upload: {r.status_code}")
    except Exception as e:
        logging.error(f"Error sending to dashboard: {e}")

def push_to_taxii(bundle, server_url, collection_id, username, password):
    try:
        server = Server(server_url, user=username, password=password)
        api_root = server.api_roots[0]
        collection = api_root.collections[collection_id]
        collection.add_objects([bundle])
        logging.info("STIX bundle pushed to TAXII server.")
    except Exception as e:
        logging.error(f"TAXII push failed: {e}")

# === Main ===
def main(args):
    setup_logging(args.log)
    logging.info("Starting Enhanced Firmware STIX Export")

    firmware_file = args.firmware
    if not os.path.exists(firmware_file):
        logging.error(f"File not found: {firmware_file}")
        return

    os.makedirs("results", exist_ok=True)
    anomaly_found, pattern, hash_val = detect_firmware_anomalies(firmware_file)

    if anomaly_found:
        killchain_stage = map_killchain_stage(pattern)
        bundle = create_stix_bundle(pattern, hash_val, os.path.basename(firmware_file), killchain_stage)
        stix_path = f"results/stix_firmware_alert_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        save_bundle(bundle, stix_path)

        if args.dashboard:
            send_to_dashboard(stix_path)

        if args.taxii:
            push_to_taxii(bundle, args.taxii, args.collection, args.user, args.password)
    else:
        logging.info("No firmware anomalies detected.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Firmware STIX Export")
    parser.add_argument("--firmware", required=True, help="Path to firmware file")
    parser.add_argument("--log", default="logs/firmware_stix.log", help="Log file path")
    parser.add_argument("--dashboard", action="store_true", help="Send alert to dashboard")
    parser.add_argument("--taxii", help="TAXII server URL")
    parser.add_argument("--collection", help="TAXII Collection ID")
    parser.add_argument("--user", help="TAXII Username")
    parser.add_argument("--password", help="TAXII Password")
    args = parser.parse_args()
    main(args)
