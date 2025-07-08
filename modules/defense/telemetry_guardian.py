#!/usr/bin/env python3
# Route: modules/defense/telemetry_guardian.py
# Description: Validates satellite telemetry using schema enforcement, HMAC signatures, and chained hash integrity

import socket
import json
import hashlib
import hmac
import base64
import time
import os
from datetime import datetime

# === Configuration ===
SECRET_KEY_PATH = "/etc/sdt_telemetry_secret.key"
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5566
BUFFER_SIZE = 4096
ALLOWED_FIELDS = {"timestamp", "satellite_id", "altitude", "velocity", "status", "signature"}
HASH_CHAIN_LOG = "/var/log/sdt_telemetry_chain.log"
ALERT_LOG = "/var/log/sdt_telemetry_guardian.log"

# === Utils ===
def sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

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

def validate_schema(data):
    return set(data.keys()) == ALLOWED_FIELDS

def load_last_hash():
    try:
        with open(HASH_CHAIN_LOG, "r") as f:
            lines = f.readlines()
            if lines:
                return lines[-1].strip().split(" | ")[1]
    except FileNotFoundError:
        return "GENESIS"
    return "GENESIS"

def append_hash_chain(packet_str, new_hash):
    ts = datetime.utcnow().isoformat()
    with open(HASH_CHAIN_LOG, "a") as f:
        f.write(f"{ts} | {new_hash} | {packet_str}\n")

# === Core Telemetry Monitor ===
def monitor_udp_telemetry():
    secret = load_secret()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    last_hash = load_last_hash()
    print(f"[*] Listening on UDP {LISTEN_PORT}...")

    while True:
        try:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            packet_str = data.decode().strip()
            try:
                packet = json.loads(packet_str)
            except json.JSONDecodeError:
                log_alert("Malformed telemetry JSON.")
                continue

            if not validate_schema(packet):
                log_alert(f"Telemetry schema violation: {packet}")
                continue

            if not verify_signature(packet, packet["signature"], secret):
                log_alert(f"Telemetry HMAC verification failed: {packet}")
                continue

            chained = last_hash + packet_str
            new_hash = sha256(chained)
            append_hash_chain(packet_str, new_hash)
            last_hash = new_hash

        except Exception as e:
            log_alert(f"Socket error: {e}")
            time.sleep(1)

def main():
    print("[*] Telemetry Guardian active. Validating telemetry over UDP...")
    monitor_udp_telemetry()

if __name__ == "__main__":
    main()
