import os
import json
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

RESULTS_DIR = "results"
HEATMAP_OUT = os.path.join(RESULTS_DIR, "attack_frequency_heatmap.png")

def parse_timestamps_from_logs():
    timestamps = []
    for fname in os.listdir(RESULTS_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(RESULTS_DIR, fname), "r") as f:
                    data = json.load(f)
                ts = data.get("timestamp") or data.get("ts")
                if ts:
                    dt = datetime.strptime(str(ts)[:14], "%Y%m%d%H%M%S")
                    timestamps.append(dt)
            except Exception:
                continue
    return timestamps

def generate_hourly_heatmap(timestamps):
    heatmap = np.zeros((7, 24))  # 7 days x 24 hours

    for dt in timestamps:
        weekday = dt.weekday()    # 0=Monday, 6=Sunday
        hour = dt.hour
        heatmap[weekday][hour] += 1

    return heatmap

def plot_heatmap(heatmap):
    plt.figure(figsize=(12, 5))
    plt.imshow(heatmap, cmap="YlOrRd", aspect="auto")
    plt.title("Attack Frequency Heatmap (Days x Hours)")
    plt.xlabel("Hour of Day")
    plt.ylabel("Day of Week")
    plt.xticks(np.arange(24), [f"{i:02d}" for i in range(24)])
    plt.yticks(np.arange(7), ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
    plt.colorbar(label="Number of Events")
    plt.tight_layout()
    plt.savefig(HEATMAP_OUT)
    print(f"[✓] Heatmap saved: {HEATMAP_OUT}")

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamps = parse_timestamps_from_logs()
    if not timestamps:
        print("[!] No timestamps found in result files.")
        return
    heatmap = generate_hourly_heatmap(timestamps)
    plot_heatmap(heatmap)

if __name__ == "__main__":
    main()
