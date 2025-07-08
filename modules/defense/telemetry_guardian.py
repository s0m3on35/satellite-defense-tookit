#!/usr/bin/env python3
# Route: modules/defense/telemetry_guardian.py
# Description: Validates telemetry messages, detects spoofing, enforces schema and cryptographic signatures

import json
import os
import hashlib
import time
from datetime import datetime
import hmac
import base64

SECRET_KEY_PATH = "/etc/sdt_telemetry_secret.key"
TELEMETRY_INPUT = "/var/telemetry/incoming.log"
ALERT_LOG = "/var/log/sdt_telemetry_guardian.log"
ALLOWED_FIELDS = {"timestamp", "satellite_id", "altitude", "velocity", "status", "signature"}

def log_alert(msg):
    ts = datetime.utcnow().isoformat()
    full = f"{ts} - ALERT: {msg}"
    with open(ALERT_LOG, "a") as f:
        f.write(full + "\n")
    os.system(f'logger -p auth.crit "{full}"')

def load_secret():
    if not os.path.exists(SECRET_KEY_PATH):
        raise FileNotFoundError("Secret key not found.")
    with open(SECRET_KEY_PATH, 'rb') as f:
        return f.read().strip()

def verify_signature(data, provided_signature, secret_key):
    filtered = {k: v for k, v in data.items() if k != "signature"}
    message = json.dumps(filtered, sort_keys=True).encode()
    expected_hmac = hmac.new(secret_key, message, hashlib.sha256).digest()
    encoded = base64.b64encode(expected_hmac).decode()
    return hmac.compare_digest(encoded, provided_signature)

def validate_structure(data):
    return set(data.keys()) == ALLOWED_FIELDS

def monitor_telemetry():
    secret = load_secret()
    with open(TELEMETRY_INPUT, 'r') as f:
        f.seek(0, os.SEEK_END)  # Tail the file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            try:
                packet = json.loads(line.strip())
            except json.JSONDecodeError:
                log_alert("Malformed telemetry JSON.")
                continue

            if not validate_structure(packet):
                log_alert(f"Schema violation in telemetry: {packet}")
                continue

            if not verify_signature(packet, packet["signature"], secret):
                log_alert(f"Telemetry signature verification failed: {packet}")
                continue

def main():
    print("[*] Telemetry Guardian active. Monitoring incoming telemetry stream...")
    monitor_telemetry()

if __name__ == "__main__":
    main()
