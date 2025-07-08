#!/usr/bin/env python3
# Route: modules/defense/rf_injection_barrier.py
# Description: Detects rogue RF signal injections targeting SATCOM and GNSS bands

import numpy as np
import subprocess
import time
import os
from datetime import datetime
from scipy.stats import entropy

CENTER_FREQ = 1575.42e6  # GNSS L1 (Hz)
BANDWIDTH = 2.5e6        # Hz
SCAN_DURATION = 5        # seconds
THRESHOLD_ENTROPY = 4.0
RTL_POWER_BIN = "/usr/bin/rtl_power"
TMP_CSV = "/tmp/rtl_scan.csv"
LOG_PATH = "/var/log/sdt_rf_barrier.log"

def log_alert(msg):
    timestamp = datetime.utcnow().isoformat()
    full_msg = f"{timestamp} - RF INJECTION BARRIER: {msg}"
    with open(LOG_PATH, "a") as f:
        f.write(full_msg + "\n")
    subprocess.call(["logger", "-p", "auth.crit", full_msg])

def run_sdr_scan():
    cmd = [
        RTL_POWER_BIN,
        "-f", f"{CENTER_FREQ - BANDWIDTH/2}:{CENTER_FREQ + BANDWIDTH/2}:1k",
        "-g", "20",
        "-i", f"{SCAN_DURATION}s",
        "-e", f"{SCAN_DURATION}s",
        TMP_CSV
    ]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log_alert(f"SDR scan failed: {e}")

def analyze_entropy():
    if not os.path.exists(TMP_CSV):
        return
    try:
        with open(TMP_CSV, "r") as f:
            lines = f.readlines()
        power_vals = []
        for line in lines:
            if line.startswith("Hz") or line.startswith("t"):
                continue
            parts = line.strip().split(",")[6:]  # skip metadata
            power_vals.extend([float(p) for p in parts if p])
        histogram, _ = np.histogram(power_vals, bins=20, density=True)
        spectrum_entropy = entropy(histogram)
        return spectrum_entropy
    except Exception as e:
        log_alert(f"Entropy analysis failed: {e}")
        return None

def monitor_rf():
    print("[*] RF Injection Barrier initialized. Monitoring GNSS band for rogue signals...")
    while True:
        run_sdr_scan()
        e_val = analyze_entropy()
        if e_val is not None:
            if e_val < THRESHOLD_ENTROPY:
                log_alert(f"Entropy anomaly detected: {e_val:.2f}. Possible RF injection.")
        time.sleep(10)

def main():
    monitor_rf()

if __name__ == "__main__":
    main()
