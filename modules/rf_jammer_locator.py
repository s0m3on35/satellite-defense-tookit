

#!/usr/bin/env python3
import argparse
import logging
import os
import numpy as np
import matplotlib.pyplot as plt
import json
import yaml
import socket
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
from scipy.stats import entropy

def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def setup_logging(log_file):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def simulate_rf_scan(freq_range, duration):
    freqs = np.linspace(freq_range[0], freq_range[1], 1000)
    signal = np.random.rand(1000)
    signal[400:420] += 8
    entropy_val = entropy(np.histogram(signal, bins=10, density=True)[0])
    return freqs, signal, entropy_val

def detect_anomalies(signal):
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    preds = clf.fit_predict(signal.reshape(-1, 1))
    return preds

def plot_heatmap(freqs, signal, anomalies, output_path):
    plt.figure(figsize=(12, 5))
    plt.plot(freqs, signal, label='Signal Strength (dB)')
    plt.scatter(freqs[anomalies == -1], signal[anomalies == -1], color='red', label='Anomalies')
    plt.axvline(freqs[np.argmax(signal)], color='black', linestyle='--', label='Peak')
    plt.title('RF Jammer Detection')
    plt.xlabel('Frequency (MHz)')
    plt.ylabel('Signal Strength')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def export_json(result, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(result, f, indent=4)

def websocket_alert(host, port, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(json.dumps(data).encode())
        s.close()
    except:
        pass

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    logging.info("RF Jammer Locator (Advanced Mode) Started")

    freq_range = config['scan_range']
    duration = config['duration']
    ws_host = config.get('websocket_host', 'localhost')
    ws_port = config.get('websocket_port', 8765)

    freqs, signal, entropy_val = simulate_rf_scan(freq_range, duration)
    peak_freq = float(freqs[np.argmax(signal)])
    peak_level = float(np.max(signal))
    anomalies = detect_anomalies(signal)

    result = {
        "timestamp": datetime.now().isoformat(),
        "peak_frequency_mhz": peak_freq,
        "peak_signal_level": peak_level,
        "entropy": entropy_val,
        "anomaly_indices": np.where(anomalies == -1)[0].tolist()
    }

    export_json(result, "results/jammer_detection.json")
    plot_heatmap(freqs, signal, anomalies, "results/jammer_scan_plot.png")
    websocket_alert(ws_host, ws_port, result)

    logging.info(f"Detected jammer at {peak_freq:.2f} MHz, entropy={entropy_val:.3f}")
    logging.info("Results saved to results/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RF Jammer Locator - Advanced")
    parser.add_argument("--config", default="config/config.yaml", help="YAML config file")
    parser.add_argument("--log", default="logs/rf_jammer.log", help="Log file path")
    args = parser.parse_args()
    main(args)
