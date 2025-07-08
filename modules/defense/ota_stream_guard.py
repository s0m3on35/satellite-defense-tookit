#!/usr/bin/env python3
# Route: modules/defense/ota_stream_guard.py
# Description: Monitors OTA firmware update streams for unauthorized uploads, anomalies, and integrity violations

import socket
import threading
import hashlib
import hmac
import base64
import os
import json
from datetime import datetime

PORT = 8899
LOG_FILE = "/var/log/sdt_ota_guardian.log"
AUTHORIZED_SIGNATURES_FILE = "/etc/sdt_ota_signatures.json"
SECRET_KEY_PATH = "/etc/sdt_ota_secret.key"
CHUNK_SIZE = 4096

def log(msg):
    ts = datetime.utcnow().isoformat()
    entry = f"{ts} - {msg}"
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")
    os.system(f'logger -p auth.crit "{entry}"')

def load_secret():
    if not os.path.exists(SECRET_KEY_PATH):
        raise FileNotFoundError("OTA guardian key missing.")
    with open(SECRET_KEY_PATH, "rb") as f:
        return f.read().strip()

def load_signatures():
    if not os.path.exists(AUTHORIZED_SIGNATURES_FILE):
        return {}
    with open(AUTHORIZED_SIGNATURES_FILE, "r") as f:
        return json.load(f)

def calculate_hmac(data, key):
    return base64.b64encode(hmac.new(key, data, hashlib.sha256).digest()).decode()

def handle_client(conn, addr, secret_key, known_sigs):
    log(f"Incoming OTA session from {addr}")
    firmware_data = b''
    try:
        while True:
            chunk = conn.recv(CHUNK_SIZE)
            if not chunk:
                break
            firmware_data += chunk
        signature = calculate_hmac(firmware_data, secret_key)
        if signature in known_sigs.values():
            log(f"Verified OTA update from {addr}")
        else:
            log(f"UNAUTHORIZED OTA UPDATE from {addr} — HMAC mismatch")
    except Exception as e:
        log(f"Error handling OTA stream from {addr}: {e}")
    finally:
        conn.close()

def start_server():
    secret_key = load_secret()
    known_sigs = load_signatures()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", PORT))
    server.listen(5)
    log(f"OTA Stream Guardian active on port {PORT}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr, secret_key, known_sigs)).start()

if __name__ == "__main__":
    start_server()
