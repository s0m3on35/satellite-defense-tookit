#!/usr/bin/env python3
# File: modules/c2/signal_aware_dead_drop_uploader.py

import os
import json
import base64
import logging
from pathlib import Path
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

CONFIG_FILE = "configs/dead_drop_config.json"
PAYLOAD_DIR = "payloads/dead_drops"
PLAINTEXT_PAYLOAD_FILE = "payloads/command.txt"
LOG_FILE = "logs/dead_drop_uploader.log"
ALERT_FILE = "webgui/alerts.json"

# Ensure directories exist
Path(CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)
Path(PAYLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
Path(ALERT_FILE).parent.mkdir(parents=True, exist_ok=True)
Path("payloads").mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def generate_default_config():
    key = get_random_bytes(16)
    config = {
        "aes_key": base64.b64encode(key).decode(),
        "method": "sdr",
        "payload_file": PLAINTEXT_PAYLOAD_FILE
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    logging.info("[+] Created default dead drop config.")
    return config

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return generate_default_config()
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def auto_create_payload(payload_path):
    if not os.path.exists(payload_path):
        with open(payload_path, "w") as f:
            f.write("echo 'Dead drop initialized'")
        logging.info(f"[+] Created default payload: {payload_path}")

def encrypt_payload(aes_key_b64, payload_text):
    key = base64.b64decode(aes_key_b64)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(payload_text.encode(), AES.block_size))
    encrypted = {
        "iv": base64.b64encode(cipher.iv).decode(),
        "ciphertext": base64.b64encode(ct_bytes).decode()
    }
    return encrypted

def write_encrypted_payload(enc, output_dir):
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = f"{output_dir}/drop_{timestamp}.b64"
    with open(output_path, "w") as f:
        json.dump(enc, f, indent=2)
    logging.info(f"[+] Encrypted payload written to {output_path}")
    return output_path

def append_alert(method):
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "dead_drop_upload",
        "method": method,
        "status": "success"
    }
    try:
        if os.path.exists(ALERT_FILE):
            with open(ALERT_FILE, "r") as f:
                alerts = json.load(f)
        else:
            alerts = []
        alerts.append(alert)
        with open(ALERT_FILE, "w") as f:
            json.dump(alerts, f, indent=2)
        logging.info(f"[+] Dashboard alert recorded.")
    except Exception as e:
        logging.warning(f"[!] Failed to write alert: {e}")

def main():
    logging.info("[*] Signal-aware Dead Drop Uploader Starting")
    cfg = load_config()
    auto_create_payload(cfg["payload_file"])

    with open(cfg["payload_file"], "r") as f:
        plaintext = f.read()

    enc_payload = encrypt_payload(cfg["aes_key"], plaintext)
    output_path = write_encrypted_payload(enc_payload, PAYLOAD_DIR)
    append_alert(cfg["method"])
    logging.info(f"[+] Dead drop completed using method: {cfg['method']}")

if __name__ == "__main__":
    main()
