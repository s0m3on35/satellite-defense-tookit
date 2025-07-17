#!/usr/bin/env python3
# File: modules/recon/passive_satellite_fingerprinter.py

import os
import time
import json
import subprocess
import threading
from datetime import datetime
from pathlib import Path
import numpy as np
import scipy.io.wavfile as wav
from scipy.fft import fft

# Paths
MODULE_ID = "passive_satellite_fingerprinter"
FINGERPRINT_DIR = "recon/satellite_fingerprints"
DATABASE_FILE = "intel/satdb_known_signatures.json"
LOG_FILE = "logs/passive_satellite_fingerprinter.log"
ALERT_FILE = "webgui/alerts.json"
KILLCHAIN_FILE = "reports/killchain.json"
STIX_EXPORT = "results/stix_satellite_fingerprints.json"

# Setup
os.makedirs(FINGERPRINT_DIR, exist_ok=True)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

def log_event(msg):
    timestamp = datetime.utcnow().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[{timestamp}] {msg}")

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
        "file": wav_file,
        "mean": float(np.mean(freqs)),
        "std_dev": float(np.std(freqs))
    }
    return fingerprint

def classify_fingerprint(fp):
    if fp["peak_magnitude"] > 1e7 and fp["std_dev"] > 2e6:
        return "suspicious_uplink"
    elif fp["std_dev"] < 5e5:
        return "beacon"
    return "telemetry"

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

def save_result(fingerprint, match, classification):
    result = {
        "timestamp": fingerprint["scan_time"],
        "matched_satellite": match["name"] if match else "Unknown",
        "classification": classification,
        "fingerprint": fingerprint,
        "match_confidence": "high" if match else "low"
    }
    out_file = f"{FINGERPRINT_DIR}/result_{int(time.time())}.json"
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)
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

def export_stix(result):
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{os.urandom(8).hex()}",
        "objects": [
            {
                "type": "observed-data",
                "id": f"observed-data--{os.urandom(8).hex()}",
                "created_by_ref": "identity--satellite-defense-toolkit",
                "created": datetime.utcnow().isoformat(),
                "first_observed": result["timestamp"],
                "last_observed": result["timestamp"],
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "x-observed-fingerprint",
                        "signal_type": result["classification"],
                        "dominant_freq_bin": result["fingerprint"]["dominant_freq_bin"],
                        "peak_magnitude": result["fingerprint"]["peak_magnitude"]
                    }
                }
            }
        ]
    }
    with open(STIX_EXPORT, "w") as f:
        json.dump(stix_bundle, f, indent=2)
    log_event("[*] STIX export complete")

def plot_waterfall(wav_file):
    try:
        from modules.recon.rf_waterfall_plotter import generate_waterfall
        generate_waterfall(wav_file)
    except Exception as e:
        log_event(f"[!] Waterfall plot error: {e}")

def update_killchain(result):
    try:
        kill_entry = {
            "module": MODULE_ID,
            "timestamp": result["timestamp"],
            "stage": "Recon",
            "details": result
        }
        if os.path.exists(KILLCHAIN_FILE):
            with open(KILLCHAIN_FILE, "r") as f:
                killchain = json.load(f)
        else:
            killchain = []
        killchain.append(kill_entry)
        with open(KILLCHAIN_FILE, "w") as f:
            json.dump(killchain, f, indent=2)
    except Exception as e:
        log_event(f"[!] Failed to update killchain: {e}")

def main():
    log_event("[*] Passive Satellite Fingerprinter Started")
    wav_file = scan_satellite_spectrum()
    fingerprint = extract_fingerprint_features(wav_file)
    classification = classify_fingerprint(fingerprint)
    known = load_known_signatures()
    match = match_fingerprint(fingerprint, known)
    result = save_result(fingerprint, match, classification)
    append_alert({
        "timestamp": result["timestamp"],
        "type": "satellite_scan_detected",
        "satellite": result["matched_satellite"],
        "classification": result["classification"],
        "confidence": result["match_confidence"]
    })
    export_stix(result)
    update_killchain(result)
    plot_waterfall(wav_file)
    log_event(f"[+] Scan complete. Match: {result['matched_satellite']}, Class: {classification}")
    log_event("[*] Module completed.")

if __name__ == "__main__":
    main()
