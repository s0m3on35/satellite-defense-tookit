#!/usr/bin/env python3
# Route: modules/defense/ota_guard.py
# Description: Monitors OTA firmware update streams, validates headers, blocks unauthorized updates, logs anomalies

import socket
import json
import hmac
import hashlib
import base64
import os
from datetime import datetime

LISTEN_PORT = 9090
SECRET_KEY_PATH = "/etc/sdt_ota_secret.key"
LOG_PATH = "/var/log/sdt_ota_guard.log"
ALLOWED_VERSIONS = {"1.0.5", "1.0.6", "2.0.0"}  # Define trusted firmware versions
ALLOWED_SOURCE_IDS = {"SAT-GW-01", "SAT-GW-02"}

def log_event(msg):
    ts = datetime.utcnow().isoformat()
    line = f"{ts} - {msg}"
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")
    os.system(f'logger -p auth.crit "{line}"')

def load_secret():
    if not os.path.exists(SECRET_KEY_PATH):
        raise FileNotFoundError("OTA secret key missing.")
    with open(SECRET_KEY_PATH, "rb") as f:
        return f.read().strip()

def verify_signature(data, provided_sig, key):
    filtered = {k: v for k, v in data.items() if k != "signature"}
    message = json.dumps(filtered, sort_keys=True).encode()
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(base64.b64encode(mac).decode(), provided_sig)

def handle_packet(packet_data, secret):
    try:
        packet = json.loads(packet_data)
    except json.JSONDecodeError:
        log_event("Malformed OTA packet received.")
        return

    if not {"firmware_version", "source_id", "timestamp", "signature"} <= set(packet.keys()):
        log_event(f"OTA schema violation: {packet}")
        return

    if packet["firmware_version"] not in ALLOWED_VERSIONS:
        log_event(f"Unauthorized firmware version detected: {packet['firmware_version']}")
        return

    if packet["source_id"] not in ALLOWED_SOURCE_IDS:
        log_event(f"Unauthorized source ID: {packet['source_id']}")
        return

    if not verify_signature(packet, packet["signature"], secret):
        log_event("OTA signature verification failed.")
        return

    log_event(f"Valid OTA update received: {packet['firmware_version']} from {packet['source_id']}")

def start_ota_guard():
    secret = load_secret()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    log_event("OTA Guard active. Listening for firmware update packets...")
    
    while True:
        data, _ = sock.recvfrom(8192)
        handle_packet(data.decode(errors="ignore"), secret)

if __name__ == "__main__":
    start_ota_guard()
