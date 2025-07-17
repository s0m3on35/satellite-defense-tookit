#!/usr/bin/env python3
# File: modules/forensics/signal_artifact_timeline_builder.py

import os
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from scipy.io import wavfile
from pathlib import Path

CAPTURE_DIR = "rf_captures"
TIMELINE_DIR = "results/signal_timelines"
LOG_FILE = "logs/signal_timeline_builder.log"
STIX_OUTPUT = "results/stix_signal_timeline.json"

Path(TIMELINE_DIR).mkdir(parents=True, exist_ok=True)
Path("logs").mkdir(exist_ok=True)

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {msg}\n")
    print(f"[+] {msg}")

def analyze_wav(file_path):
    sample_rate, data = wavfile.read(file_path)
    if data.ndim > 1:
        data = data[:, 0]

    abs_data = np.abs(data)
    threshold = np.percentile(abs_data, 98)
    burst_indices = np.where(abs_data > threshold)[0]

    bursts = []
    if len(burst_indices) > 0:
        time_stamps = burst_indices / sample_rate
        previous = time_stamps[0]
        burst_start = previous
        for t in time_stamps[1:]:
            if t - previous > 0.1:  # gap of 100ms
                bursts.append({"start": burst_start, "end": previous})
                burst_start = t
            previous = t
        bursts.append({"start": burst_start, "end": previous})

    return sample_rate, bursts

def build_timeline(file_path):
    filename = os.path.basename(file_path)
    log(f"[+] Processing {filename}")
    sample_rate, bursts = analyze_wav(file_path)

    timeline = {
        "file": filename,
        "timestamp": datetime.utcnow().isoformat(),
        "sample_rate": sample_rate,
        "num_bursts": len(bursts),
        "bursts": bursts
    }

    timeline_file = os.path.join(TIMELINE_DIR, f"{filename}_timeline.json")
    with open(timeline_file, "w") as f:
        json.dump(timeline, f, indent=2)

    log(f"[✓] Timeline saved: {timeline_file}")
    export_stix(timeline)
    plot_bursts(timeline, filename)

def export_stix(timeline):
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--signal-{timeline['file']}",
        "spec_version": "2.1",
        "objects": [{
            "type": "observed-data",
            "id": f"observed-data--{timeline['file']}",
            "first_observed": timeline["timestamp"],
            "last_observed": timeline["timestamp"],
            "number_observed": timeline["num_bursts"],
            "x_signal_bursts": timeline["bursts"],
            "x_sample_rate": timeline["sample_rate"],
            "x_capture_file": timeline["file"]
        }]
    }
    with open(STIX_OUTPUT, "w") as f:
        json.dump(stix_bundle, f, indent=2)
    log(f"[+] STIX exported to {STIX_OUTPUT}")

def plot_bursts(timeline, filename):
    times = [b["start"] for b in timeline["bursts"]]
    durations = [b["end"] - b["start"] for b in timeline["bursts"]]

    plt.figure(figsize=(10, 4))
    plt.bar(times, durations, width=0.05, color="cyan", edgecolor="blue")
    plt.title(f"Signal Burst Timeline: {filename}")
    plt.xlabel("Time (s)")
    plt.ylabel("Burst Duration (s)")
    plt.grid(True)
    out_path = os.path.join(TIMELINE_DIR, f"{filename}_bursts.png")
    plt.savefig(out_path)
    plt.close()
    log(f"[✓] Burst plot saved: {out_path}")

def main():
    log("[*] Starting signal artifact timeline builder...")
    targets = [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".wav")]
    if not targets:
        log("[!] No .wav RF capture files found.")
        return
    for f in targets:
        build_timeline(os.path.join(CAPTURE_DIR, f))

if __name__ == "__main__":
    main()
