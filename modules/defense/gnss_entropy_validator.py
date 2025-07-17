#!/usr/bin/env python3
# GNSS Entropy Validator - Satellite Defense Toolkit
# Monitors GNSS feed for entropy irregularities and spoofing signals

import os
import time
import json
import random
import logging
from datetime import datetime
from statistics import stdev, mean
from stix2 import Bundle, Indicator, ObservedData

# === Config ===
GNSS_FEED = "logs/gnss_feed.jsonl"  # Example of GPS/RTK log source
ALERT_FILE = "webgui/alerts.json"
STIX_OUT = "results/stix/gnss_entropy_stix_bundle.json"
LOG_FILE = "logs/gnss_entropy_validator.log"
WINDOW_SIZE = 10
ENTROPY_THRESHOLD = 0.00001  # Very small stddev = suspicious spoof
STEALTH_MODE = False

# === Setup ===
os.makedirs("results/stix", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def read_recent_coords():
    coords = []
    try:
        with open(GNSS_FEED, "r") as f:
            lines = f.readlines()[-WINDOW_SIZE:]
            for line in lines:
                try:
                    entry = json.loads(line)
                    lat = float(entry.get("latitude", 0))
                    lon = float(entry.get("longitude", 0))
                    coords.append((lat, lon))
                except Exception:
                    continue
    except FileNotFoundError:
        return []
    return coords

def compute_entropy(coords):
    if len(coords) < 3:
        return 1.0  # Not enough data to decide
    lats = [c[0] for c in coords]
    lons = [c[1] for c in coords]
    lat_std = stdev(lats)
    lon_std = stdev(lons)
    entropy = lat_std * lon_std
    return entropy

def log_alert(entropy, coords):
    timestamp = datetime.utcnow().isoformat()
    reason = f"Low entropy GNSS anomaly detected: {entropy:.8f}"
    entry = {
        "timestamp": timestamp,
        "module": "GNSS Entropy Validator",
        "alert": reason,
        "coordinates": coords
    }

    # Alert JSON
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            try:
                alerts = json.load(f)
            except json.JSONDecodeError:
                alerts = []
    else:
        alerts = []

    alerts.append(entry)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    logging.warning(reason)
    generate_stix(entropy, coords)

def generate_stix(entropy, coords):
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    coord_str = "|".join([f"{lat:.5f},{lon:.5f}" for lat, lon in coords])

    indicator = Indicator(
        name="GNSS Entropy Anomaly",
        description="Anomalously low entropy in GNSS signal indicates spoofing or jamming.",
        pattern=f"[x-location:lat_long = '{coord_str}']",
        valid_from=now,
        labels=["gnss", "spoofing", "signal", "entropy"]
    )

    observed = ObservedData(
        first_observed=now,
        last_observed=now,
        number_observed=1,
        objects={"0": {
            "type": "x-location",
            "lat_long": coord_str,
            "entropy": entropy
        }}
    )

    bundle = Bundle(indicator, observed)
    with open(STIX_OUT, "w") as f:
        f.write(bundle.serialize(pretty=True))

def monitor_entropy():
    print("[*] GNSS Entropy Validator started.") if not STEALTH_MODE else None
    while True:
        coords = read_recent_coords()
        entropy = compute_entropy(coords)
        if entropy < ENTROPY_THRESHOLD:
            log_alert(entropy, coords)
        if not STEALTH_MODE:
            print(f"[+] Entropy: {entropy:.8f}")
        time.sleep(5)

if __name__ == "__main__":
    try:
        monitor_entropy()
    except KeyboardInterrupt:
        print("[!] Stopped by user.")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
