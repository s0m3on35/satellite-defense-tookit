#!/usr/bin/env python3
# File: modules/forensics/satellite_telemetry_playback.py

import os
import sys
import time
import json
import csv
import base64
from pathlib import Path
from datetime import datetime

PLAYBACK_FOLDER = "captures/telemetry/"
ALERT_FILE = "webgui/alerts.json"
LOG_FILE = "logs/telemetry_playback.log"
DASHBOARD_WS_FILE = "webgui/ws_events.jsonl"

Path("logs").mkdir(exist_ok=True)
Path("webgui").mkdir(exist_ok=True)

def log(msg):
    timestamp = datetime.utcnow().isoformat()
    print(f"[{timestamp}] {msg}")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

def send_to_dashboard(payload):
    try:
        with open(DASHBOARD_WS_FILE, "a") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        log(f"[!] Failed to log dashboard payload: {e}")

def parse_telemetry_line(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        try:
            decoded = base64.b64decode(line).decode()
            data = json.loads(decoded)
        except Exception:
            return None
    return data

def load_telemetry_file(filepath):
    ext = filepath.split(".")[-1]
    data = []
    try:
        if ext == "json":
            with open(filepath, "r") as f:
                lines = f.readlines()
                for line in lines:
                    record = parse_telemetry_line(line.strip())
                    if record:
                        data.append(record)
        elif ext == "csv":
            with open(filepath, newline='') as f:
                reader = csv.DictReader(f)
                data = list(reader)
        elif ext == "bin":
            with open(filepath, "rb") as f:
                raw = f.read().decode(errors="ignore").split("\n")
                for line in raw:
                    record = parse_telemetry_line(line.strip())
                    if record:
                        data.append(record)
    except Exception as e:
        log(f"[!] Error reading file {filepath}: {e}")
    return data

def detect_anomalies(record):
    anomalies = []
    try:
        for key, value in record.items():
            if isinstance(value, (int, float)):
                if key.lower() in ["voltage", "temp", "temperature"] and (value < -50 or value > 100):
                    anomalies.append(f"{key} out of bounds: {value}")
                if "error" in key.lower() and value != 0:
                    anomalies.append(f"{key} error value: {value}")
    except Exception as e:
        log(f"[!] Anomaly check failed: {e}")
    return anomalies

def append_alert(anomaly, timestamp):
    try:
        alert = {
            "timestamp": timestamp,
            "type": "telemetry_anomaly",
            "details": anomaly
        }
        if os.path.exists(ALERT_FILE):
            with open(ALERT_FILE, "r") as f:
                alerts = json.load(f)
        else:
            alerts = []
        alerts.append(alert)
        with open(ALERT_FILE, "w") as f:
            json.dump(alerts, f, indent=2)
        log(f"[!] ALERT: {anomaly}")
    except Exception as e:
        log(f"[!] Failed to write alert: {e}")

def playback(file_path, delay=1.0):
    log(f"[+] Starting playback for: {file_path}")
    telemetry = load_telemetry_file(file_path)
    if not telemetry:
        log("[!] No data found to play.")
        return

    for record in telemetry:
        ts = datetime.utcnow().isoformat()
        log(f"[>] {record}")
        send_to_dashboard({"event": "telemetry", "timestamp": ts, "data": record})

        anomalies = detect_anomalies(record)
        for a in anomalies:
            append_alert(a, ts)

        time.sleep(delay)

    log("[✓] Playback finished.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.json|file.csv|file.bin> [delay_seconds]")
        return

    file_path = sys.argv[1]
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

    if not os.path.isfile(file_path):
        file_path = os.path.join(PLAYBACK_FOLDER, file_path)

    if not os.path.isfile(file_path):
        log(f"[!] File not found: {file_path}")
        return

    playback(file_path, delay)

if __name__ == "__main__":
    main()
