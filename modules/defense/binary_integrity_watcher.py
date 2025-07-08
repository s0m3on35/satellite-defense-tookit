#!/usr/bin/env python3
# Route: modules/defense/binary_integrity_watcher.py
# Description: Monitors critical binaries for unauthorized tampering using secure hash validation

import os
import time
import json
import hashlib
import subprocess
from datetime import datetime

BASELINE_FILE = "/etc/sdt_binary_integrity_baseline.json"
ALERT_LOG = "/var/log/sdt_binary_integrity_alerts.log"
CHECK_INTERVAL = 60  # seconds

MONITORED_BINARIES = [
    "/bin/busybox",
    "/usr/bin/python3",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/bin/bash",
    # Add more high-risk executables as needed
]

def compute_sha256(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def log_alert(message, critical=False):
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"{timestamp} - {message}"
    with open(ALERT_LOG, 'a') as f:
        f.write(log_entry + '\n')
    if critical:
        try:
            subprocess.call(['logger', '-p', 'auth.crit', log_entry])
        except:
            pass

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_baseline(data):
    with open(BASELINE_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def baseline_files():
    data = {}
    for path in MONITORED_BINARIES:
        if os.path.exists(path):
            sha = compute_sha256(path)
            data[path] = sha
    save_baseline(data)

def monitor_binaries():
    baseline = load_baseline()
    for path in MONITORED_BINARIES:
        if not os.path.exists(path):
            log_alert(f"Critical binary missing: {path}", critical=True)
            continue
        current_hash = compute_sha256(path)
        if path not in baseline:
            log_alert(f"Unrecognized binary: {path}. No baseline entry.", critical=True)
        elif current_hash != baseline[path]:
            log_alert(f"Binary tampering detected: {path}", critical=True)

if __name__ == "__main__":
    print("[*] Launching binary integrity watcher...")
    if not os.path.exists(BASELINE_FILE):
        print("[*] No baseline detected. Creating initial hash baseline.")
        baseline_files()

    while True:
        monitor_binaries()
        time.sleep(CHECK_INTERVAL)
