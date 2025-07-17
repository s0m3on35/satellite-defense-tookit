#!/usr/bin/env python3
# File: modules/recon/sdr_burst_signal_detector.py

import os
import time
import json
import threading
import subprocess
import numpy as np
from datetime import datetime
from scipy.signal import spectrogram
from pathlib import Path
import matplotlib.pyplot as plt

OUTPUT_DIR = "recon/burst_detections"
ALERT_FILE = "webgui/alerts.json"
BURST_LOG = "logs/burst_signal_detector.log"
WATERFALL_IMG = f"{OUTPUT_DIR}/burst_waterfall_{int(time.time())}.png"
BURST_RAW_FILE = f"{OUTPUT_DIR}/burst_iq_{int(time.time())}.bin"

os.makedirs(OUTPUT_DIR, exist_ok=True)
Path("logs").mkdir(parents=True, exist_ok=True)

def log_event(message):
    timestamp = datetime.utcnow().isoformat()
    with open(BURST_LOG, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[+] {message}")

def record_iq_sample(freq="137.5M", sample_rate="2.4e6", gain="30", duration=10):
    log_event(f"Recording IQ sample @ {freq}Hz for {duration}s...")
    cmd = [
        "rtl_sdr", "-f", freq, "-s", str(int(float(sample_rate))),
        "-g", gain, BURST_RAW_FILE
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    return BURST_RAW_FILE

def analyze_burst(iq_file):
    with open(iq_file, "rb") as f:
        raw = np.frombuffer(f.read(), dtype=np.uint8)
    iq = (raw[::2] - 127.5) + 1j * (raw[1::2] - 127.5)
    power = np.abs(iq)**2

    entropy = -np.sum((power / np.sum(power)) * np.log2((power / np.sum(power)) + 1e-12))
    bursts = detect_bursts(power)

    log_event(f"Entropy: {entropy:.2f}, Burst Count: {len(bursts)}")
    return {
        "entropy": entropy,
        "burst_count": len(bursts),
        "bursts": bursts,
        "timestamp": datetime.utcnow().isoformat()
    }

def detect_bursts(power, threshold_factor=4.5):
    mean_power = np.mean(power)
    threshold = threshold_factor * mean_power
    burst_indices = np.where(power > threshold)[0]
    bursts = np.split(burst_indices, np.where(np.diff(burst_indices) > 100)[0] + 1)
    return [b.tolist() for b in bursts if len(b) > 100]

def generate_waterfall_plot(iq_file, output_image):
    with open(iq_file, "rb") as f:
        raw = np.frombuffer(f.read(), dtype=np.uint8)
    iq = (raw[::2] - 127.5) + 1j * (raw[1::2] - 127.5)

    f, t, Sxx = spectrogram(iq, fs=2.4e6, nperseg=2048)
    plt.figure(figsize=(10, 4))
    plt.pcolormesh(t, f / 1e6, 10 * np.log10(Sxx), shading='gouraud')
    plt.ylabel('Frequency [MHz]')
    plt.xlabel('Time [s]')
    plt.title('RF Waterfall Plot')
    plt.colorbar(label='Power [dB]')
    plt.tight_layout()
    plt.savefig(output_image)
    plt.close()

def append_alert(result):
    alert = {
        "timestamp": result["timestamp"],
        "type": "rf_burst_detected",
        "burst_count": result["burst_count"],
        "entropy": result["entropy"],
        "image": WATERFALL_IMG
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
        log_event(f"[!] Failed to write alert: {e}")

def main():
    log_event("Starting SDR Burst Signal Detector...")
    iq_file = record_iq_sample()
    result = analyze_burst(iq_file)
    generate_waterfall_plot(iq_file, WATERFALL_IMG)
    append_alert(result)
    log_event("Detection complete.")

if __name__ == "__main__":
    main()
