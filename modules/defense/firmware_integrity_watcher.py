#!/usr/bin/env python3
# Route: modules/defense/firmware_integrity_watcher.py
# Description: Monitors firmware binaries for unauthorized changes using secure hashing (SHA-512 + optional HMAC)

import os
import hashlib
import hmac
import json
import time
from datetime import datetime

WATCH_PATHS = ["/firmware/flight.bin", "/firmware/nav_controller.img"]
HASH_DB_PATH = "/etc/sdt_firmware_hashes.json"
SECRET_KEY_PATH = "/etc/sdt_firmware_integrity.key"
LOG_FILE = "/var/log/sdt_firmware_integrity.log"
USE_HMAC = True  # Set to False if no secret key is used

def log(msg):
    ts = datetime.utcnow().isoformat()
    line = f"{ts} - {msg}"
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    os.system(f'logger -p auth.crit "{line}"')

def load_secret():
    if not os.path.exists(SECRET_KEY_PATH):
        raise FileNotFoundError("Missing integrity key.")
    with open(SECRET_KEY_PATH, "rb") as f:
        return f.read().strip()

def compute_digest(path, key=None):
    hasher = hashlib.sha512()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    digest = hasher.digest()
    return hmac.new(key, digest, hashlib.sha256).hexdigest() if key else hasher.hexdigest()

def load_baselines():
    if not os.path.exists(HASH_DB_PATH):
        log("Baseline hash database not found.")
        return {}
    with open(HASH_DB_PATH, "r") as f:
        return json.load(f)

def monitor():
    key = load_secret() if USE_HMAC else None
    baselines = load_baselines()

    while True:
        for path in WATCH_PATHS:
            if not os.path.exists(path):
                log(f"Missing watched firmware: {path}")
                continue
            try:
                current_hash = compute_digest(path, key)
                if path not in baselines:
                    log(f"New firmware hash added for {path}")
                    baselines[path] = current_hash
                    with open(HASH_DB_PATH, "w") as f:
                        json.dump(baselines, f, indent=2)
                    continue
                if baselines[path] != current_hash:
                    log(f"Firmware tampering detected in {path}")
            except Exception as e:
                log(f"Error while checking {path}: {str(e)}")
        time.sleep(300)

if __name__ == "__main__":
    log("Firmware Integrity Watcher started.")
    monitor()
