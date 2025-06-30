import argparse
import logging
import os
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import yaml
import json
from sklearn.ensemble import IsolationForest
import paho.mqtt.publish as publish

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

def simulate_or_load_sdr_scan(freq_range, duration, source_file=None):
    if source_file and os.path.exists(source_file):
        data = np.load(source_file)
        return data['freqs'], data['signal']
    freqs = np.linspace(freq_range[0], freq_range[1], 1000)
    signal = np.random.rand(1000)
    signal[400:420] += 8
    return freqs, signal

def calculate_entropy(signal):
    hist, _ = np.histogram(signal, bins=50, density=True)
    hist += 1e-10
    return -np.sum(hist * np.log2(hist))

def detect_anomalies(signal, contamination=0.02):
    data = np.array(signal).reshape(-1, 1)
    model = IsolationForest(contamination=contamination, random_state=42)
    preds = model.fit_predict(data)
    scores = model.decision_function(data)
    return preds, scores

def plot_heatmap(freqs, signal, output_path):
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, signal, label='Signal Strength (dB)')
    plt.title('SDR Frequency Scan')
    plt.xlabel('Frequency (MHz)')
    plt.ylabel('Signal Level')
    plt.axvline(freqs[np.argmax(signal)], color='red', linestyle='--', label='Jammer Peak')
    plt.legend()
    plt.grid(True)
    plt.savefig(output_path)
    plt.close()

def plot_anomaly_scores(scores, output_path):
    plt.figure(figsize=(10, 3))
    plt.plot(scores, label='Anomaly Scores')
    plt.axhline(np.mean(scores), color='orange', linestyle='--', label='Mean Score')
    plt.title('Anomaly Detection (Isolation Forest)')
    plt.xlabel('Frequency Bin')
    plt.ylabel('Score')
    plt.legend()
    plt.grid(True)
    plt.savefig(output_path)
    plt.close()

def publish_alert_mqtt(broker, topic, payload):
    try:
        publish.single(topic, json.dumps(payload), hostname=broker)
    except Exception as e:
        logging.warning(f"MQTT publish failed: {e}")

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    os.makedirs("results", exist_ok=True)
    logging.info("RF Jammer Locator Started")

    freq_range = config['scan_range']
    duration = config['duration']
    source_file = config.get('input_file', None)
    mqtt_broker = config.get('mqtt_broker', None)

    freqs, signal = simulate_or_load_sdr_scan(freq_range, duration, source_file)
    entropy = calculate_entropy(signal)
    logging.info(f"Signal entropy: {entropy:.4f}")

    preds, scores = detect_anomalies(signal)
    anomaly_bins = np.where(preds == -1)[0].tolist()
    peak_freq = float(freqs[np.argmax(signal)])
    peak_level = float(np.max(signal))

    result = {
        "timestamp": datetime.now().isoformat(),
        "peak_frequency_mhz": peak_freq,
        "peak_signal_level": peak_level,
        "entropy": entropy,
        "anomalous_bins": anomaly_bins,
        "scan_range": freq_range
    }

    with open("results/jammer_detection.json", "w") as f:
        json.dump(result, f, indent=4)

    np.savez("results/jammer_capture.npz", freqs=freqs, signal=signal)
    plot_heatmap(freqs, signal, "results/jammer_scan_plot.png")
    plot_anomaly_scores(scores, "results/jammer_anomaly_scores.png")

    if mqtt_broker:
        publish_alert_mqtt(mqtt_broker, "satellite/jammer_alert", result)

    logging.info(f"Jammer detected at {peak_freq:.2f} MHz with signal {peak_level:.2f} dB")
    logging.info(f"Anomalies found at bins: {anomaly_bins}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RF Jammer Locator (Advanced)")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/jammer_locator.log", help="Log file path")
    args = parser.parse_args()
    main(args)
