#!/usr/bin/env python3
# Route: modules/defense/interface_integrity_monitor.py
# Description: High-assurance interface integrity monitor for critical systems (satellite/embedded)

import os
import json
import time
import hashlib
import socket
import subprocess
from datetime import datetime

BASELINE_FILE = "/etc/sdt_interface_baseline.json"
ALERT_LOG = "/var/log/sdt_interface_alerts.log"
CHECK_INTERVAL = 30  # Seconds

def secure_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def get_interfaces():
    try:
        return [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']
    except:
        return []

def get_mac(iface):
    try:
        return open(f"/sys/class/net/{iface}/address").read().strip()
    except:
        return "unknown"

def get_ip(iface):
    try:
        result = subprocess.check_output(f"ip -4 addr show {iface}", shell=True).decode()
        for line in result.splitlines():
            if "inet " in line:
                return line.strip().split()[1].split('/')[0]
    except:
        return "unknown"

def build_interface_profile(iface):
    return {
        "mac": get_mac(iface),
        "ip": get_ip(iface),
        "hash": secure_hash(f"{iface}:{get_mac(iface)}:{get_ip(iface)}")
    }

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_baseline(data):
    with open(BASELINE_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def log_alert(message, critical=False):
    timestamp = datetime.utcnow().isoformat()
    entry = f"{timestamp} - {message}"
    with open(ALERT_LOG, 'a') as logf:
        logf.write(entry + '\n')
    if critical:
        try:
            subprocess.call(['logger', '-p', 'auth.crit', entry])
        except:
            pass

def detect_interface_anomalies():
    current_state = {}
    baseline = load_baseline()
    interfaces = get_interfaces()

    for iface in interfaces:
        profile = build_interface_profile(iface)
        current_state[iface] = profile

        if iface not in baseline:
            log_alert(f"New interface detected: {iface}", critical=True)
        else:
            base = baseline[iface]
            if profile['mac'] != base['mac']:
                log_alert(f"MAC address mismatch on {iface}: expected {base['mac']}, found {profile['mac']}", critical=True)
            if profile['ip'] != base['ip']:
                log_alert(f"IP change on {iface}: expected {base['ip']}, found {profile['ip']}")
            if profile['hash'] != base['hash']:
                log_alert(f"Interface hash mismatch on {iface}. Possible tampering.", critical=True)

    for iface in baseline:
        if iface not in current_state:
            log_alert(f"Interface missing: {iface}", critical=True)

    save_baseline(current_state)

if __name__ == "__main__":
    print("[*] Starting high-assurance interface integrity monitor.")
    while True:
        detect_interface_anomalies()
        time.sleep(CHECK_INTERVAL)
