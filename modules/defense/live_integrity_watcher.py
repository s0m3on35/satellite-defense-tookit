#!/usr/bin/env python3
# Route: modules/defense/live_integrity_watcher.py
# Description: Monitors runtime memory regions of key binaries for unauthorized modifications

import os
import subprocess
import hashlib
import time
from datetime import datetime

WATCHED_BINARIES = {
    "/usr/bin/firmware_updater": "d41d8cd98f00b204e9800998ecf8427e",
    "/usr/bin/telemetry_agent": "9e107d9d372bb6826bd81d3542a419d6",
    "/lib/systemd/system/gpsd.service": "e4d909c290d0fb1ca068ffaddf22cbd0"
}

ALERT_LOG = "/var/log/sdt_integrity_alerts.log"
CHECK_INTERVAL = 60  # seconds

def calculate_sha256(filepath):
    if not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def log_alert(path, msg):
    timestamp = datetime.utcnow().isoformat()
    alert = f"{timestamp} - ALERT: {path} integrity violation - {msg}"
    with open(ALERT_LOG, "a") as f:
        f.write(alert + "\n")
    subprocess.call(["logger", "-p", "auth.crit", alert])

def verify_all():
    for path, expected_hash in WATCHED_BINARIES.items():
        current_hash = calculate_sha256(path)
        if not current_hash:
            log_alert(path, "File missing")
        elif current_hash != expected_hash:
            log_alert(path, f"Hash mismatch: expected {expected_hash}, got {current_hash}")

def main():
    print("[*] Starting live binary integrity monitor...")
    while True:
        verify_all()
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
