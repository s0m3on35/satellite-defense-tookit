
#!/usr/bin/env python3

import os
import hashlib
import time
import logging
import requests

FIRMWARE_PATH = "/opt/satellite/firmware/current.bin"
HASH_STORE = "/opt/satellite/firmware/.firmware_hash"
WEBHOOK_URL = "http://localhost:8081/webhook"
LOG_FILE = "/var/log/firmware_watcher.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

def get_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def send_alert(message):
    try:
        requests.post(WEBHOOK_URL, json={"alert": message})
    except Exception as e:
        logging.warning(f"Failed to send webhook: {e}")

print("[*] Starting Firmware Watcher Agent...")

while True:
    try:
        if not os.path.exists(FIRMWARE_PATH):
            logging.warning("Firmware file not found.")
            time.sleep(10)
            continue

        current_hash = get_sha256(FIRMWARE_PATH)

        if not os.path.exists(HASH_STORE):
            with open(HASH_STORE, "w") as f:
                f.write(current_hash)
                logging.info("Baseline firmware hash stored.")
        else:
            with open(HASH_STORE, "r") as f:
                stored_hash = f.read().strip()
                if current_hash != stored_hash:
                    alert = f"⚠️ Firmware tampering detected! Current hash: {current_hash}"
                    logging.warning(alert)
                    send_alert(alert)
                    with open(HASH_STORE, "w") as f2:
                        f2.write(current_hash)
    except Exception as e:
        logging.error(f"Exception in watcher loop: {e}")
    time.sleep(30)
