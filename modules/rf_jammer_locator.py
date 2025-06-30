import argparse
import logging
import os
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import yaml
import json
import socket
import subprocess
from sklearn.ensemble import IsolationForest
from scipy.stats import entropy

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

def simulate_or_real_scan(freq_range, use_real=False, output_csv=None):
    if use_real and output_csv:
        subprocess.run([
            "rtl_power", "-f", f"{freq_range[0]}M:{freq_range[1]}M:1M", 
            "-g", "20", "-i", "1", "-e", "10s", "-c", "20", "-o", output_csv
        ])
        data = np.loadtxt(output_csv, delimiter=',', skiprows=1)
        freqs = data[:, 0]
        signal = data[:, 1]
    else:
        freqs = np.linspace(freq_range[0], freq_range[1], 1000)
        signal = np.random.rand(1000)
        signal[400:420] += 8
    return freqs, signal

def analyze_entropy(signal):
    hist, _ = np.histogram(signal, bins=50, density=True)
    return entropy(hist)

def fingerprint(signal):
    return list(np.round(signal[:50], 2))

def detect_anomalies(signal):
    clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    signal_reshaped = np.array(signal).reshape(-1, 1)
    preds = clf.fit_predict(signal_reshaped)
    scores = clf.decision_function(signal_reshaped)
    return preds, scores

def plot_scan(freqs, signal, output_path):
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, signal, label='Signal Strength (dB)')
    plt.axvline(freqs[np.argmax(signal)], color='red', linestyle='--', label='Jammer Peak')
    plt.title('RF Spectrum Scan')
    plt.xlabel('Frequency (MHz)')
    plt.ylabel('Signal Level')
    plt.legend()
    plt.grid(True)
    plt.savefig(output_path)
    plt.close()

def send_websocket_alert(data, ws_host="localhost", ws_port=8765):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ws_host, ws_port))
        s.sendall((json.dumps(data) + "\n").encode())
        s.close()
    except Exception as e:
        logging.warning(f"WebSocket alert failed: {e}")

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)

    freq_range = config['scan_range']
    duration = config['duration']
    use_real = config.get('use_real_sdr', False)

    freqs, signal = simulate_or_real_scan(freq_range, use_real, config.get('sdr_output_csv'))

    peak_freq = freqs[np.argmax(signal)]
    peak_level = float(np.max(signal))
    entropy_val = analyze_entropy(signal)
    fingerprint_val = fingerprint(signal)
    preds, scores = detect_anomalies(signal)

    os.makedirs("results", exist_ok=True)

    result = {
        "timestamp": datetime.now().isoformat(),
        "peak_frequency_mhz": float(peak_freq),
        "peak_signal_level": peak_level,
        "entropy": float(entropy_val),
        "fingerprint": fingerprint_val,
        "alerts": int(sum(np.array(preds) == -1))
    }

    with open("results/jammer_detection.json", "w") as f:
        json.dump(result, f, indent=4)

    np.savez("results/jammer_signal_snapshot.npz", freqs=freqs, signal=signal)
    plot_scan(freqs, signal, "results/jammer_scan_plot.png")

    send_websocket_alert({
        "agent": "rf_jammer_locator",
        "type": "rf",
        "alert": f"Jammer at {peak_freq:.2f} MHz, {peak_level:.2f} dB",
        "entropy": entropy_val,
        "timestamp": result["timestamp"]
    })

    logging.info(f"Jammer detected at {peak_freq:.2f} MHz with signal {peak_level:.2f} dB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced RF Jammer Locator")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/jammer_locator.log", help="Log file path")
    args = parser.parse_args()
    main(args)
