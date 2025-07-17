#!/usr/bin/env python3
# File: modules/recon/passive_satellite_fingerprinter.py

import os
import time
import json
import subprocess
import threading
from datetime import datetime
from pathlib import Path

FINGERPRINT_DIR = "recon/satellite_fingerprints"
DATABASE_FILE = "intel/satdb_known_signatures.json"
LOG_FILE = "logs/passive_satellite_fingerprinter.log"
ALERT_FILE = "webgui/alerts.json"

os.makedirs(FINGERPRINT_DIR, exist_ok=True)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

def log_event(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {msg}\n")
    print(msg)

def scan_satellite_spectrum(center_freq="137.5M", duration_sec=20):
    output_file = f"{FINGERPRINT_DIR}/scan_{int(time.time())}.wav"
    cmd = [
        "rtl_fm", "-f", center_freq, "-M", "fm", "-s", "22050",
        "-g", "30", "-E", "deemp", "-F", "9", output_file
    ]
    log_event(f"[+] Starting RTL scan on {center_freq}Hz for {duration_sec}s")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration_sec)
    proc.terminate()
    return output_file

def extract_fingerprint_features(wav_file):
    import numpy as np
    import scipy.io.wavfile as wav
    from scipy.fft import fft

    samplerate, data = wav.read(wav_file)
    if data.ndim > 1:
        data = data[:, 0]
    N = len(data)
    yf = fft(data)
    freqs = np.abs(yf[:N // 2])
    dominant = int(np.argmax(freqs))
    fingerprint = {
        "dominant_freq_bin": dominant,
        "peak_magnitude": float(np.max(freqs)),
        "scan_time": datetime.utcnow().isoformat(),
        "file": wav_file
    }
    return fingerprint

def load_known_signatures():
    if os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, "r") as f:
            return json.load(f)
    return []

def match_fingerprint(fp, db):
    tolerance = 5
    for entry in db:
        if abs(entry["dominant_freq_bin"] - fp["dominant_freq_bin"]) <= tolerance:
            return entry
    return None

def save_result(fingerprint, match):
    result = {
        "timestamp": fingerprint["scan_time"],
        "matched_satellite": match["name"] if match else "Unknown",
        "fingerprint": fingerprint,
        "match_confidence": "high" if match else "low"
    }
    out_file = f"{FINGERPRINT_DIR}/result_{int(time.time())}.json"
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)
    if match:
        alert = {
            "timestamp": result["timestamp"],
            "type": "satellite_fingerprint_match",
            "satellite": match["name"],
            "confidence": "high"
        }
        append_alert(alert)
    return result

def append_alert(alert):
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
        log_event(f"[!] Failed to write alert: {e}")

def main():
    log_event("[*] Passive Satellite Fingerprinter Started")
    wav_file = scan_satellite_spectrum()
    fingerprint = extract_fingerprint_features(wav_file)
    known = load_known_signatures()
    match = match_fingerprint(fingerprint, known)
    result = save_result(fingerprint, match)
    log_event(f"[+] Scan complete. Result: {result['matched_satellite']}")
    log_event("[*] Module completed.")

if __name__ == "__main__":
    main()
