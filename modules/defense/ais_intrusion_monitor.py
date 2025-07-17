#!/usr/bin/env python3
# AIS Intrusion Monitor - Satellite Defense Toolkit
# Monitors AIS traffic for unauthorized or spoofed maritime broadcasts

import socket
import json
import time
import logging
import os
from datetime import datetime
from stix2 import Bundle, Indicator, ObservedData
from hashlib import sha256

# === Config ===
UDP_IP = "0.0.0.0"
UDP_PORT = 10110  # Standard AIS UDP input port
LOG_FILE = "logs/ais_intrusion_monitor.log"
ALERT_FILE = "webgui/alerts.json"
STIX_BUNDLE_PATH = "results/stix/ais_intrusion_stix_bundle.json"
STEALTH_MODE = False
BLACKLISTED_MMSI = {"999999999", "000000000"}  # Example MMSI values

# === Setup ===
os.makedirs("logs", exist_ok=True)
os.makedirs("results/stix", exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def generate_stix_bundle(entry):
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    unique_hash = sha256(entry.encode()).hexdigest()

    indicator = Indicator(
        name="Suspicious AIS Transmission",
        description="AIS packet matched blacklist or spoof pattern",
        pattern=f"[network-traffic:extensions.'network-traffic-ext'.payload_bin = '{entry}']",
        valid_from=now,
        labels=["ais", "spoofing", "recon"],
        id=f"indicator--{unique_hash[:8]}"
    )

    observed = ObservedData(
        first_observed=now,
        last_observed=now,
        number_observed=1,
        objects={"0": {
            "type": "network-traffic",
            "extensions": {
                "network-traffic-ext": {
                    "payload_bin": entry
                }
            }
        }},
        id=f"observed-data--{unique_hash[8:16]}"
    )

    bundle = Bundle(indicator, observed)
    with open(STIX_BUNDLE_PATH, "w") as f:
        f.write(bundle.serialize(pretty=True))

def log_alert(payload, reason):
    timestamp = datetime.utcnow().isoformat()
    entry = {
        "timestamp": timestamp,
        "module": "AIS Intrusion Monitor",
        "alert": reason,
        "payload": payload
    }

    # Append to alert JSON
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

    logging.warning(f"{reason} | Payload: {payload}")
    generate_stix_bundle(payload)

def is_suspicious(message):
    try:
        # Example pattern match (NMEA-encoded AIS)
        if "!AIVDM" not in message:
            return False
        if any(mmsi in message for mmsi in BLACKLISTED_MMSI):
            return True
        if message.count(",") < 5:
            return True  # Malformed
        if "REPLAY" in message or "TEST" in message:
            return True
        return False
    except Exception as e:
        logging.error(f"Detection error: {e}")
        return False

def listen_udp():
    logging.info("Starting AIS Intrusion Monitor...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    logging.info(f"Listening on UDP {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(4096)
        message = data.decode(errors="ignore").strip()

        if not STEALTH_MODE:
            print(f"[UDP] {addr[0]}: {message}")

        if is_suspicious(message):
            log_alert(message, "Suspicious AIS message detected")

if __name__ == "__main__":
    try:
        listen_udp()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    except Exception as ex:
        logging.error(f"Fatal error: {ex}")
