
import argparse
import logging
import json
import yaml
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from datetime import datetime
import websocket
import threading

os.makedirs("results", exist_ok=True)
os.makedirs("logs", exist_ok=True)
os.makedirs("config", exist_ok=True)

def send_ws_alert(alert_data, ws_url="ws://localhost:8765"):
    def _send():
        try:
            ws = websocket.create_connection(ws_url)
            ws.send(json.dumps(alert_data))
            ws.close()
        except:
            pass
    threading.Thread(target=_send).start()

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

def load_data(input_path):
    if input_path.endswith('.json'):
        with open(input_path, 'r') as f:
            raw = json.load(f)
        return np.array([[d.get('lat', 0), d.get('lon', 0), d.get('alt', 0)] for d in raw])
    elif input_path.endswith('.csv'):
        df = pd.read_csv(input_path)
        return df.iloc[:, :3].values
    elif input_path.endswith('.nmea'):
        parsed = []
        with open(input_path, 'r') as f:
            for line in f:
                if line.startswith('$GPGGA'):
                    parts = line.strip().split(',')
                    try:
                        lat = float(parts[2]) if parts[2] else 0
                        lon = float(parts[4]) if parts[4] else 0
                        alt = float(parts[9]) if parts[9] else 0
                        parsed.append([lat, lon, alt])
                    except:
                        continue
        return np.array(parsed)
    else:
        raise ValueError("Unsupported file format.")

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    logging.info("GNSS AI Anomaly Detector Started")

    if not os.path.exists(args.input):
        logging.error("Input file not found.")
        return

    data = load_data(args.input)
    if data.shape[0] < 10:
        logging.error("Insufficient data points.")
        return

    preds, scores = detect_anomalies(data, contamination=config['contamination'])

    results = []
    for i, (score, label) in enumerate(zip(scores, preds)):
        result = {
            "timestamp": datetime.now().isoformat(),
            "point_id": i,
            "anomaly_score": float(score),
            "is_anomaly": int(label == -1)
        }
        results.append(result)
        if result["is_anomaly"]:
            send_ws_alert({
                "agent": "gnss_ai_detector",
                "type": "gnss",
                "alert": f"GNSS anomaly at point {i} with score {score}",
                "timestamp": result["timestamp"]
            })

    with open("results/gnss_anomalies.json", "w") as f:
        json.dump(results, f, indent=4)

    plot_scores(scores, "results/gnss_anomaly_plot.png")

    killchain_entry = {
        "agent": "gnss_ai_detector",
        "step": "GNSS_Anomaly_Detected",
        "timestamp": datetime.now().isoformat(),
        "count": sum(1 for r in results if r["is_anomaly"])
    }
    with open("results/killchain.json", "a") as f:
        f.write(json.dumps(killchain_entry) + "\n")

    logging.info("Detection complete. Results saved.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GNSS AI Anomaly Detector (Advanced)")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/gnss_detector.log", help="Log file path")
    parser.add_argument("--input", required=True, help="GNSS data input file (.json/.csv/.nmea)")
    args = parser.parse_args()
    main(args)
