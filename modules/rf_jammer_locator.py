
import argparse
import logging
import os
import json
import yaml
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.ensemble import IsolationForest
from scipy.stats import entropy
from scipy.io import wavfile
import socket

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

def simulate_sdr_signal(freq_range):
    freqs = np.linspace(freq_range[0], freq_range[1], 1024)
    signal = np.random.normal(0, 0.5, 1024)
    signal[420:440] += np.random.normal(12, 2, 20)
    return freqs, signal

def compute_entropy(signal):
    hist, _ = np.histogram(signal, bins=64)
    hist = hist + 1e-6
    return float(entropy(hist, base=2))

def detect_anomalies(signal, contamination):
    clf = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    scores = clf.fit_predict(signal.reshape(-1, 1))
    return scores

def export_plot(freqs, signal, anomalies, output_path):
    plt.figure(figsize=(12, 4))
    plt.plot(freqs, signal, label="Signal (dB)")
    plt.scatter(freqs[anomalies == -1], signal[anomalies == -1], color='red', label="Anomalies")
    plt.axvline(freqs[np.argmax(signal)], color='magenta', linestyle='--', label="Jammer Peak")
    plt.xlabel("Frequency (MHz)")
    plt.ylabel("Power Level")
    plt.grid(True)
    plt.legend()
    plt.savefig(output_path)
    plt.close()

def export_wav(signal, path):
    normalized = np.int16((signal / np.max(np.abs(signal))) * 32767)
    wavfile.write(path, 44100, normalized)

def export_pcap_stub(signal, path):
    with open(path, "wb") as f:
        f.write(b"PCAP_PLACEHOLDER_START")
        f.write(signal.tobytes())
        f.write(b"PCAP_PLACEHOLDER_END")

def send_websocket_alert(result, ws_host, ws_port):
    try:
        payload = json.dumps(result)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ws_host, ws_port))
        sock.sendall(payload.encode())
        sock.close()
    except Exception as e:
        logging.error(f"WebSocket alert failed: {e}")

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)

    freqs, signal = simulate_sdr_signal(config["scan_range"])
    anomalies = detect_anomalies(signal, config.get("contamination", 0.05))
    entropy_val = compute_entropy(signal)
    peak_freq = float(freqs[np.argmax(signal)])
    peak_db = float(np.max(signal))

    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().isoformat()

    result = {
        "timestamp": timestamp,
        "peak_freq_mhz": peak_freq,
        "peak_db": peak_db,
        "entropy": entropy_val,
        "anomalies_detected": int(np.sum(anomalies == -1)),
        "uuid": f"jammer-{int(time.time())}"
    }

    json_path = f"results/jammer_{int(time.time())}.json"
    with open(json_path, "w") as f:
        json.dump(result, f, indent=4)

    export_plot(freqs, signal, anomalies, f"results/jammer_plot.png")
    export_wav(signal, "results/jammer_audio.wav")
    export_pcap_stub(signal, "results/jammer_capture.pcap")

    if config.get("websocket_enabled"):
        send_websocket_alert(result, config["ws_host"], config["ws_port"])

    logging.info(f"Jammer peak: {peak_freq:.2f} MHz | Entropy: {entropy_val:.2f}")
    logging.info(f"Results saved: {json_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced RF Jammer Locator")
    parser.add_argument("--config", default="config/config.yaml", help="YAML config path")
    parser.add_argument("--log", default="logs/rf_jammer_locator.log", help="Log output path")
    args = parser.parse_args()
    main(args)
