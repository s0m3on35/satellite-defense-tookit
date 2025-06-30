
import argparse
import logging
import os
import numpy as np
import matplotlib.pyplot as plt
import json
from datetime import datetime
import yaml
from scipy.stats import entropy
from sklearn.cluster import DBSCAN

# === Config & Logging Setup ===
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

# === SDR Jammer Scan Simulation ===
def simulate_sdr_scan(freq_range, duration):
    freqs = np.linspace(freq_range[0], freq_range[1], 1000)
    signal = np.random.normal(0, 1, 1000)
    signal[400:420] += 8
    return freqs, signal

# === Entropy Calculation ===
def calculate_entropy(signal):
    hist, _ = np.histogram(signal, bins=50, density=True)
    return entropy(hist + 1e-8)

# === Clustering for Jamming Zones ===
def cluster_signal(signal, eps=0.5, min_samples=5):
    reshaped = signal.reshape(-1, 1)
    model = DBSCAN(eps=eps, min_samples=min_samples)
    return model.fit_predict(reshaped)

# === Plotting ===
def plot_heatmap(freqs, signal, path):
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, signal, label='Signal Strength (dB)')
    plt.axvline(freqs[np.argmax(signal)], color='red', linestyle='--', label='Jammer Peak')
    plt.title('SDR Frequency Scan')
    plt.xlabel('Frequency (MHz)')
    plt.ylabel('Signal Level')
    plt.grid(True)
    plt.legend()
    plt.savefig(path)
    plt.close()

def plot_entropy_histogram(signal, path):
    hist, bins = np.histogram(signal, bins=50)
    plt.figure(figsize=(10, 4))
    plt.bar(bins[:-1], hist, width=np.diff(bins), edgecolor="black", align="edge")
    plt.title('Signal Entropy Histogram')
    plt.xlabel('Signal Level')
    plt.ylabel('Frequency')
    plt.savefig(path)
    plt.close()

# === Output Chaining ===
def export_json(result, path):
    with open(path, 'w') as f:
        json.dump(result, f, indent=4)

def create_placeholder_pcap(path):
    with open(path, 'wb') as f:
        f.write(b'\xd4\xc3\xb2\xa1')  # Magic number for PCAP global header

# === Main Execution ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)

    freq_range = config['scan_range']
    duration = config['duration']

    freqs, signal = simulate_sdr_scan(freq_range, duration)
    peak_freq = freqs[np.argmax(signal)]
    peak_level = float(np.max(signal))
    entropy_score = calculate_entropy(signal)
    clusters = cluster_signal(signal)

    os.makedirs("results", exist_ok=True)

    result = {
        "timestamp": datetime.now().isoformat(),
        "peak_frequency_mhz": float(peak_freq),
        "peak_signal_level": peak_level,
        "signal_entropy": entropy_score,
        "cluster_labels": clusters.tolist()
    }

    export_json(result, "results/jammer_detection.json")
    plot_heatmap(freqs, signal, "results/jammer_scan_plot.png")
    plot_entropy_histogram(signal, "results/jammer_entropy_hist.png")
    create_placeholder_pcap("results/jammer_capture.pcap")

    alert = {
        "agent": "rf_jammer_locator",
        "type": "rf",
        "alert": f"Jammer peak at {peak_freq:.2f} MHz",
        "timestamp": datetime.now().isoformat()
    }

    with open("webgui/alerts.json", "a") as f:
        f.write(json.dumps(alert) + "\n")

    logging.info(f"Jammer detected at {peak_freq:.2f} MHz | Entropy: {entropy_score:.3f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RF Jammer Locator (Advanced)")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/jammer_locator.log", help="Log file path")
    args = parser.parse_args()
    main(args)
