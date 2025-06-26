
import argparse
import logging
import yaml
import os
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

# === Config & Logging ===
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

# === Simulated LSTM Monitoring ===
def simulate_telemetry_stream(n_points=150):
    normal = np.random.normal(0, 1, (n_points, 1))
    anomaly = np.random.normal(5, 0.5, (10, 1))
    data = np.vstack([normal, anomaly])
    return data.flatten()

def detect_anomalies(data, threshold):
    mean = np.mean(data)
    std = np.std(data)
    z_scores = (data - mean) / std
    anomalies = np.abs(z_scores) > threshold
    return anomalies, z_scores

def plot_anomalies(data, anomalies, output_path):
    plt.figure(figsize=(10, 4))
    plt.plot(data, label='Telemetry')
    plt.plot(np.where(anomalies)[0], data[anomalies], 'ro', label='Anomalies')
    plt.title('Telemetry Anomaly Detection')
    plt.legend()
    plt.savefig(output_path)
    plt.close()

# === Main ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    logging.info("Telemetry LSTM Monitor Started")

    threshold = config['threshold']
    telemetry_data = simulate_telemetry_stream()

    anomalies, z_scores = detect_anomalies(telemetry_data, threshold)

    os.makedirs("results", exist_ok=True)
    event_log = []
    for i, (value, is_anom, z) in enumerate(zip(telemetry_data, anomalies, z_scores)):
        if is_anom:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "point_id": i,
                "value": float(value),
                "z_score": float(z),
                "alert": "ANOMALY_DETECTED"
            }
            event_log.append(entry)

    with open("results/telemetry_anomalies.json", "w") as f:
        json.dump(event_log, f, indent=4)

    plot_anomalies(telemetry_data, anomalies, "results/telemetry_anomaly_plot.png")
    logging.info(f"Detected {len(event_log)} anomalies saved to results/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Telemetry LSTM Monitor (simulated)")
    parser.add_argument("--config", default="config/config.yaml", help="YAML config path")
    parser.add_argument("--log", default="logs/telemetry_monitor.log", help="Log file path")
    args = parser.parse_args()
    main(args)
