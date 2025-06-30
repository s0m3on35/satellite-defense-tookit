import os
import json
import logging
import yaml
import argparse
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import websocket
import requests

MITRE_DB_PATH = "data/local_mitre_db.json"
ANOMALY_PATH = "results/telemetry_anomalies.json"
SVG_OUTPUT_PATH = "results/mitre_matrix.svg"
WEBSOCKET_URL = "ws://localhost:8080/ws"
WEBHOOK_URL = "http://localhost:5000/webhook"

# === Local MITRE JSON Bootstrap ===
DEFAULT_MITRE_DATA = [
    {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"},
    {"tactic": "Defense Evasion", "technique": "Obfuscated Files or Information", "id": "T1027"},
    {"tactic": "Credential Access", "technique": "Credential Dumping", "id": "T1003"},
    {"tactic": "Discovery", "technique": "System Information Discovery", "id": "T1082"},
    {"tactic": "Impact", "technique": "Data Manipulation", "id": "T1565"},
]

# === Setup ===
def setup_logging():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename="logs/mitre_mapper.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def load_mitre_db():
    if not os.path.exists(MITRE_DB_PATH):
        os.makedirs(os.path.dirname(MITRE_DB_PATH), exist_ok=True)
        with open(MITRE_DB_PATH, "w") as f:
            json.dump(DEFAULT_MITRE_DATA, f, indent=4)
        logging.info("Created default MITRE local DB.")
    with open(MITRE_DB_PATH) as f:
        return json.load(f)

def load_anomalies(path=ANOMALY_PATH):
    with open(path) as f:
        return json.load(f)

# === Auto Matching ===
def match_anomalies_to_mitre(anomalies, mitre_db):
    matches = []
    for a in anomalies:
        if float(a["z_score"]) > 3.0:
            # Dummy logic: high z-score => critical match
            match = mitre_db[hash(a["point_id"]) % len(mitre_db)]
            matches.append({**a, **match})
    return matches

# === SVG Matrix Generator ===
def generate_svg_matrix(matches, mitre_db, output_path):
    tactics = sorted(set(m["tactic"] for m in mitre_db))
    techniques = sorted(set(m["technique"] for m in mitre_db))
    tactic_idx = {t: i for i, t in enumerate(tactics)}
    technique_idx = {t: i for i, t in enumerate(techniques)}

    fig, ax = plt.subplots(figsize=(12, 6))
    for m in matches:
        x = tactic_idx[m["tactic"]]
        y = technique_idx[m["technique"]]
        ax.add_patch(Rectangle((x, y), 1, 1, color='red', alpha=0.7))
        ax.text(x + 0.5, y + 0.5, m["id"], ha='center', va='center', color='white', fontsize=6)

    ax.set_xticks(range(len(tactics)))
    ax.set_yticks(range(len(techniques)))
    ax.set_xticklabels(tactics, rotation=45, ha='right', fontsize=8)
    ax.set_yticklabels(techniques, fontsize=6)
    ax.set_xlim(0, len(tactics))
    ax.set_ylim(0, len(techniques))
    ax.set_title("MITRE ATT&CK Matrix (Matched Anomalies)")
    plt.tight_layout()
    fig.savefig(output_path, format='svg')
    plt.close()
    logging.info(f"Saved MITRE matrix to {output_path}")

# === Alerting ===
def send_alert_webhook(matches):
    payload = {
        "type": "MITRE_TTP_ALERT",
        "timestamp": datetime.now().isoformat(),
        "match_count": len(matches),
        "matches": matches
    }
    try:
        requests.post(WEBHOOK_URL, json=payload)
        logging.info("Webhook alert sent.")
    except Exception as e:
        logging.warning(f"Webhook error: {e}")

def send_alert_websocket(matches):
    try:
        ws = websocket.create_connection(WEBSOCKET_URL)
        ws.send(json.dumps({
            "event": "TTP_MATCH",
            "timestamp": datetime.now().isoformat(),
            "matches": matches
        }))
        ws.close()
        logging.info("WebSocket alert sent.")
    except Exception as e:
        logging.warning(f"WebSocket error: {e}")

# === Main ===
def main():
    setup_logging()
    logging.info("MITRE Mapper started")
    mitre_db = load_mitre_db()
    anomalies = load_anomalies()
    matches = match_anomalies_to_mitre(anomalies, mitre_db)

    os.makedirs("results", exist_ok=True)
    with open("results/matched_ttp_events.json", "w") as f:
        json.dump(matches, f, indent=4)

    generate_svg_matrix(matches, mitre_db, SVG_OUTPUT_PATH)

    if len(matches) > 2:
        send_alert_webhook(matches)
        send_alert_websocket(matches)

    logging.info(f"{len(matches)} MITRE TTPs matched.")

if __name__ == "__main__":
    main()
