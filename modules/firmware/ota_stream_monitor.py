# modules/firmware/ota_stream_monitor.py
import argparse
import os
import hashlib
import time
import json
from datetime import datetime

STIX_OUTPUT = "results/stix_ota_alert.json"
WATCH_DIR = "logs/ota_streams"
os.makedirs(WATCH_DIR, exist_ok=True)

def hash_chunk(chunk):
    return hashlib.sha256(chunk).hexdigest()

def monitor_ota_stream(file_path, interval=5):
    seen_hashes = set()
    print(f"[+] Monitoring OTA stream: {file_path}")
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                time.sleep(interval)
                continue

            h = hash_chunk(chunk)
            if h in seen_hashes:
                print(f"[!] Potential replayed chunk: {h}")
                generate_stix_alert(file_path, h, replay=True)
            else:
                seen_hashes.add(h)

def generate_stix_alert(source, chunk_hash, replay=False):
    alert = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{hashlib.md5(chunk_hash.encode()).hexdigest()}",
        "created": datetime.utcnow().isoformat() + "Z",
        "pattern": f"[file:hashes.'SHA-256' = '{chunk_hash}']",
        "labels": ["ota-replay" if replay else "ota-stream"],
        "name": "OTA Replay Detection",
        "description": f"Detected replayed OTA firmware chunk from source {source}"
    }
    with open(STIX_OUTPUT, "w") as f:
        json.dump(alert, f, indent=2)
    print(f"[+] STIX alert written to {STIX_OUTPUT}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stream", required=True, help="OTA binary stream file to monitor")
    parser.add_argument("--interval", type=int, default=5, help="Seconds between checks")
    args = parser.parse_args()

    monitor_ota_stream(args.stream, args.interval)
