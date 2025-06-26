
import argparse
import logging
import json
import yaml
import os
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from datetime import datetime

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

# === GNSS Anomaly Detection ===
def detect_anomalies(data, contamination):
    clf = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    preds = clf.fit_predict(data)
    scores = clf.decision_function(data)
    return preds, scores

def plot_scores(scores, output_path):
    plt.figure(figsize=(10, 4))
    plt.plot(scores, label='Anomaly Score')
    plt.axhline(np.mean(scores), color='red', linestyle='--', label='Mean Threshold')
    plt.title('GNSS Anomaly Detection Score')
    plt.legend()
    plt.savefig(output_path)
    plt.close()

# === Main Execution ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)

    logging.info("GNSS Anomaly Detector Started")

    # Simulated input: Random data for example
    np.random.seed(42)
    normal_data = np.random.normal(0, 1, (100, 3))
    anomaly_data = np.random.normal(6, 1, (10, 3))
    data = np.vstack([normal_data, anomaly_data])

    preds, scores = detect_anomalies(data, contamination=config['contamination'])

    results = []
    for i, (score, label) in enumerate(zip(scores, preds)):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "point_id": i,
            "anomaly_score": float(score),
            "is_anomaly": int(label == -1)
        }
        results.append(entry)

    os.makedirs("results", exist_ok=True)
    with open("results/gnss_anomalies.json", "w") as f:
        json.dump(results, f, indent=4)

    plot_scores(scores, "results/gnss_anomaly_plot.png")
    logging.info("Detection complete. Results saved in results/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GNSS AI Anomaly Detector")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/gnss_detector.log", help="Log file path")
    args = parser.parse_args()
    main(args)
