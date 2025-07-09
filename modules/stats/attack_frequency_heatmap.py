#!/usr/bin/env python3
# Ruta: modules/stats/attack_frequency_heatmap.py

import os
import json
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from datetime import datetime
from dateutil.parser import parse as dateparse

RESULTS_DIR = "results"
HEATMAP_IMG = os.path.join(RESULTS_DIR, "attack_frequency_heatmap.png")
CSV_EXPORT = os.path.join(RESULTS_DIR, "attack_frequency_matrix.csv")

def parse_timestamps_from_logs():
    timestamps = []
    for fname in os.listdir(RESULTS_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(RESULTS_DIR, fname), "r") as f:
                    data = json.load(f)

                ts = data.get("timestamp") or data.get("ts") or data.get("created")
                if isinstance(ts, (int, float)):
                    dt = datetime.utcfromtimestamp(ts)
                elif isinstance(ts, str):
                    if ts.isdigit() and len(ts) >= 14:
                        dt = datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
                    else:
                        dt = dateparse(ts)
                else:
                    continue

                timestamps.append(dt)
            except Exception:
                continue
    return timestamps

def generate_hourly_heatmap(timestamps):
    heatmap = np.zeros((7, 24))  # 7 days (rows) x 24 hours (cols)
    for dt in timestamps:
        weekday = dt.weekday()  # 0 = Monday
        hour = dt.hour
        heatmap[weekday][hour] += 1
    return heatmap

def export_heatmap_csv(matrix):
    df = pd.DataFrame(matrix,
        index=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        columns=[f"{i:02d}" for i in range(24)]
    )
    df.to_csv(CSV_EXPORT)
    print(f"[✓] CSV matrix exported: {CSV_EXPORT}")

def plot_heatmap(matrix):
    plt.figure(figsize=(12, 5))
    plt.imshow(matrix, cmap="inferno", aspect="auto")
    plt.title("Attack Frequency Heatmap (Days x Hours)")
    plt.xlabel("Hour of Day")
    plt.ylabel("Day of Week")
    plt.xticks(np.arange(24), [f"{i:02d}" for i in range(24)])
    plt.yticks(np.arange(7), ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
    plt.colorbar(label="Number of Events")
    plt.grid(False)
    plt.tight_layout()
    plt.savefig(HEATMAP_IMG)
    print(f"[✓] Heatmap image saved: {HEATMAP_IMG}")

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamps = parse_timestamps_from_logs()
    if not timestamps:
        print("[!] No timestamps found in result files.")
        return
    matrix = generate_hourly_heatmap(timestamps)
    plot_heatmap(matrix)
    export_heatmap_csv(matrix)

if __name__ == "__main__":
    main()
