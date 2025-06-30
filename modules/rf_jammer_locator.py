# modules/rf_jammer_locator.py

import argparse
import logging
import os
import json
import yaml
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.cluster import DBSCAN
from scipy.stats import entropy
from websocket import create_connection
import subprocess
import tempfile
import serial

AGENT_ID = "rf_jammer_locator"

def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def detect_sdr_tool():
    for tool in ["rtl_power", "hackrf_transfer"]:
        if shutil.which(tool):
            return tool
    return None

def run_rtl_power(freq_range, duration, resolution):
    start, stop = freq_range
    hz_step = int((stop - start) * 1e6 / resolution)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        out_file = tf.name
    cmd = [
        "rtl_power",
        "-f", f"{start}M:{stop}M:{hz_step}",
        "-i", f"{duration}s",
        "-e", f"{duration + 2}s",
        "-o", out_file
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return parse_rtl_output(out_file)

def parse_rtl_output(path):
    freqs = []
    powers = []
    with open(path, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            hz_low = float(parts[2])
            hz_step = float(parts[3])
            n_bins = int(parts[4])
            p_values = list(map(float, parts[6:6+n_bins]))
            f_bins = [hz_low + i * hz_step for i in range(n_bins)]
            freqs.extend(f_bins)
            powers.extend(p_values)
    return np.array(freqs) / 1e6, np.array(powers)

def get_gps():
    try:
        with serial.Serial("/dev/ttyUSB0", 9600, timeout=1) as ser:
            for _ in range(10):
                line = ser.readline().decode(errors="ignore")
                if "$GPGGA" in line:
                    parts = line.split(",")
                    lat = convert_gps(parts[2], parts[3])
                    lon = convert_gps(parts[4], parts[5])
                    return {"lat": lat, "lon": lon}
    except:
        return {"lat": None, "lon": None}
    return {"lat": None, "lon": None}

def convert_gps(coord, direction):
    if not coord:
        return None
    deg = float(coord[:2])
    minutes = float(coord[2:]) / 60
    val = deg + minutes
    if direction in ['S', 'W']:
        val = -val
    return round(val, 6)

def calculate_entropy(signal):
    hist, _ = np.histogram(signal, bins=50, density=True)
    hist += 1e-8
    return float(entropy(hist))

def detect_clusters(freqs, signal, threshold):
    idx = np.where(signal > threshold)[0]
    if len(idx) == 0:
        return []
    points = np.column_stack((freqs[idx], signal[idx]))
    model = DBSCAN(eps=0.5, min_samples=2).fit(points)
    clusters = {}
    for i, label in enumerate(model.labels_):
        if label == -1:
            continue
        clusters.setdefault(label, []).append((points[i][0], points[i][1]))
    return clusters

def plot_spectrum(freqs, signal, clusters, output):
    plt.figure(figsize=(12, 5))
    plt.plot(freqs, signal, label='Signal Strength')
    for label, points in clusters.items():
        points = np.array(points)
        plt.scatter(points[:, 0], points[:, 1], label=f'Cluster {label}')
    plt.title("RF Spectrum Analysis")
    plt.xlabel("Frequency (MHz)")
    plt.ylabel("Signal Strength (dB)")
    plt.grid(True)
    plt.legend()
    plt.savefig(output)
    plt.close()

def push_ws_alert(agent_id, alert_data):
    try:
        ws = create_connection("ws://localhost:8765")
        alert_data["agent"] = agent_id
        alert_data["timestamp"] = datetime.now().isoformat()
        ws.send(json.dumps(alert_data))
        ws.close()
    except Exception:
        pass

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    os.makedirs("results", exist_ok=True)

    freq_range = config['scan_range']
    duration = config['duration']
    resolution = config.get('resolution', 1000)
    threshold = config.get('threshold', 6.0)

    freqs, signal = run_rtl_power(freq_range, duration, resolution)
    peak_freq = float(freqs[np.argmax(signal)])
    peak_signal = float(np.max(signal))
    entropy_score = calculate_entropy(signal)
    clusters = detect_clusters(freqs, signal, threshold)
    gps = get_gps()

    alert = {
        "peak_freq_mhz": peak_freq,
        "peak_signal_db": peak_signal,
        "entropy": entropy_score,
        "cluster_count": len(clusters),
        "location": gps,
        "alert": "JAMMER_DETECTED"
    }

    with open("results/jammer_detection.json", "w") as f:
        json.dump(alert, f, indent=4)

    plot_spectrum(freqs, signal, clusters, "results/jammer_plot.png")
    push_ws_alert(AGENT_ID, alert)

    logging.info(f"Detection completed: Peak @ {peak_freq:.2f} MHz | Signal {peak_signal:.2f} dB | Entropy {entropy_score:.4f}")

if __name__ == "__main__":
    import shutil
    parser = argparse.ArgumentParser(description="RF Jammer Locator (Real SDR + GPS)")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/jammer_locator.log", help="Log file path")
    args = parser.parse_args()
    main(args)
