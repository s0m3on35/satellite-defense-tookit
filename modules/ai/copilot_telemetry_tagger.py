#!/usr/bin/env python3
# Copilot Telemetry Anomaly Tagger - Satellite Defense Toolkit

import os
import json
import time
import logging
from datetime import datetime
from sklearn.ensemble import IsolationForest
import numpy as np

TELEMETRY_FILE = "logs/telemetry_stream.jsonl"
TAGGED_OUTPUT = "results/telemetry_tagged.json"
ALERT_FILE = "webgui/alerts.json"
MODEL_FILE = "models/isolation_model.npy"
LOG_FILE = "logs/copilot_telemetry_tagger.log"
STIX_FILE = "results/stix/copilot_anomaly_bundle.json"

os.makedirs("results/stix", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# === Example labels we auto-tag ===
TAG_LABELS = {
    "temp_spike": "Thermal Anomaly",
    "signal_drop": "Signal Loss",
    "unauth_cmd": "Unauthorized Command Response",
    "orbit_drift": "Trajectory Error",
    "unknown": "Unknown Anomaly"
}

# === Load basic anomaly detector (can be retrained) ===
def load_model():
    try:
        return np.load(MODEL_FILE, allow_pickle=True).item()
    except:
        return IsolationForest(n_estimators=50, contamination=0.1, random_state=42)

def tag_anomaly(vector):
    clf = load_model()
    try:
        score = clf.decision_function([vector])[0]
        prediction = clf.predict([vector])[0]
        return prediction, score
    except Exception as e:
        logging.error(f"Tagging error: {e}")
        return -1, 0.0

def classify(vector):
    if vector[0] > 100:
        return "temp_spike"
    elif vector[1] < 5:
        return "signal_drop"
    elif vector[2] == 1:
        return "unauth_cmd"
    elif vector[3] > 1.5:
        return "orbit_drift"
    return "unknown"

def export_alert(tag, vector, source="telemetry"):
    timestamp = datetime.utcnow().isoformat()
    entry = {
        "timestamp": timestamp,
        "module": "Copilot Telemetry Tagger",
        "alert": TAG_LABELS.get(tag, "Unknown"),
        "vector": vector.tolist() if isinstance(vector, np.ndarray) else vector
    }

    if os.path.exists(ALERT_FILE):
        try:
            with open(ALERT_FILE, "r") as f:
                alerts = json.load(f)
        except:
            alerts = []
    else:
        alerts = []

    alerts.append(entry)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    export_stix(tag, entry)

def export_stix(tag, entry):
    from stix2 import Bundle, Indicator, ObservedData

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    pattern = f"[x-sat:telemetry_tag = '{tag}']"
    indicator = Indicator(
        name="Copilot Tagged Anomaly",
        pattern=pattern,
        labels=["telemetry", "anomaly", tag],
        valid_from=now
    )

    observed = ObservedData(
        first_observed=now,
        last_observed=now,
        number_observed=1,
        objects={"0": {
            "type": "x-sat",
            "telemetry_tag": tag,
            "raw_data": entry["vector"]
        }}
    )

    bundle = Bundle(indicator, observed)
    with open(STIX_FILE, "w") as f:
        f.write(bundle.serialize(pretty=True))

def run_tagger():
    print("[*] Copilot Telemetry Tagger Active")
    seen = set()
    tagged = []

    while True:
        try:
            with open(TELEMETRY_FILE, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            time.sleep(3)
            continue

        for line in lines[-30:]:
            if line in seen:
                continue
            seen.add(line)
            try:
                row = json.loads(line)
                vector = np.array([
                    row.get("temperature", 0),
                    row.get("signal_strength", 0),
                    int(row.get("unauth_cmd_flag", 0)),
                    row.get("orbit_drift", 0.0)
                ])
                tag = classify(vector)
                pred, score = tag_anomaly(vector)
                if pred == -1:
                    export_alert(tag, vector)
                    tagged.append({**row, "tag": tag})
            except Exception as e:
                logging.error(f"Processing error: {e}")
        with open(TAGGED_OUTPUT, "w") as f:
            json.dump(tagged[-50:], f, indent=2)
        time.sleep(4)

if __name__ == "__main__":
    try:
        run_tagger()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
