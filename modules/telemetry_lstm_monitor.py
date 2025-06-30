import argparse
import logging
import yaml
import os
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import socket
import platform
import websocket

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

def simulate_telemetry_stream(n_points=150):
    normal = np.random.normal(0, 1, (n_points, 1))
    anomaly = np.random.normal(5, 0.5, (10, 1))
    data = np.vstack([normal, anomaly])
    return data.flatten()

def detect_anomalies(data, threshold):
    mean = np.mean(data)
    std = np.std(data)
    rolling_std = np.std(data[-30:])
    z_scores = (data - mean) / (rolling_std if rolling_std > 0 else std)
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

def send_ws_alert(ws_url, alert):
    try:
        ws = websocket.create_connection(ws_url, timeout=3)
        ws.send(json.dumps(alert))
        ws.close()
    except Exception as e:
        logging.warning(f"WebSocket alert failed: {e}")

def log_to_agent_inventory(alert):
    os.makedirs("recon", exist_ok=True)
    path = "recon/agent_inventory.json"
    agent_id = socket.gethostname()
    if os.path.exists(path):
        with open(path, "r") as f:
            agents = json.load(f)
    else:
        agents = {}
    if agent_id not in agents:
        agents[agent_id] = {
            "telemetry": [],
            "ip": socket.gethostbyname(socket.gethostname()),
            "os": platform.system(),
            "host": agent_id
        }
    agents[agent_id]["telemetry"].append(alert)
    with open(path, "w") as f:
        json.dump(agents, f, indent=2)

def generate_stix_event(alert):
    stix = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "created": datetime.utcnow().isoformat(),
        "name": "Telemetry Anomaly",
        "description": f"Detected anomaly at point {alert['point_id']}",
        "pattern": "[x-telemetry:anomaly_score > 3]",
        "pattern_type": "stix",
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "collection"}],
        "labels": ["anomaly", "telemetry", "ai"]
    }
    return stix

def export_report(alerts):
    os.makedirs("reports", exist_ok=True)
    with open("reports/telemetry_anomalies_stix.json", "w") as f:
        stix_alerts = [generate_stix_event(alert) for alert in alerts]
        json.dump(stix_alerts, f, indent=4)

    with open("reports/telemetry_report.md", "w") as f:
        for alert in alerts:
            f.write(f"- **Time**: {alert['timestamp']} | **Point**: {alert['point_id']} | **Value**: {alert['value']} | **Z**: {alert['z_score']}\n")

def enrich_with_ttp(alert):
    alert["mapped_ttp"] = "T1046"  # Network Service Scanning (example)
    alert["kill_chain"] = "collection"
    return alert

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    logging.info("Telemetry LSTM Monitor Started")

    telemetry_data = simulate_telemetry_stream()
    anomalies, z_scores = detect_anomalies(telemetry_data, config['threshold'])

    os.makedirs("results", exist_ok=True)
    alert_log = []
    for i, (val, is_anom, z) in enumerate(zip(telemetry_data, anomalies, z_scores)):
        if is_anom:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "point_id": i,
                "value": float(val),
                "z_score": float(z),
                "alert": "ANOMALY_DETECTED"
            }
            alert = enrich_with_ttp(alert)
            alert_log.append(alert)
            log_to_agent_inventory(alert)
            send_ws_alert(config.get("ws_url", "ws://localhost:8765"), alert)

    with open("results/telemetry_anomalies.json", "w") as f:
        json.dump(alert_log, f, indent=4)

    plot_anomalies(telemetry_data, anomalies, "results/telemetry_anomaly_plot.png")
    export_report(alert_log)
    logging.info(f"Detected {len(alert_log)} anomalies. Reports generated.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Telemetry LSTM Monitor (enhanced full)")
    parser.add_argument("--config", default="config/config.yaml", help="YAML config path")
    parser.add_argument("--log", default="logs/telemetry_monitor.log", help="Log file path")
    args = parser.parse_args()
    main(args)
