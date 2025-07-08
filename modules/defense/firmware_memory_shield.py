#!/usr/bin/env python3
# Route: modules/defense/firmware_memory_shield.py
# Description: Enforces runtime firmware memory protection and tamper detection

import os
import psutil
import time
import hashlib
from datetime import datetime
import subprocess

PROTECTED_BINARIES = ["/boot/firmware.bin", "/opt/satcom/main_firmware.elf"]
HASH_LOG = "/etc/sdt_firmware_hashes.json"
ALERT_LOG = "/var/log/sdt_memory_shield.log"

def log_alert(msg):
    timestamp = datetime.utcnow().isoformat()
    full = f"{timestamp} - ALERT: {msg}"
    with open(ALERT_LOG, "a") as f:
        f.write(full + "\n")
    subprocess.call(["logger", "-p", "auth.crit", full])

def sha256sum(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log_alert(f"Error hashing {filepath}: {e}")
        return None

def get_suspicious_processes():
    suspects = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = " ".join(proc.info['cmdline'])
            if any(keyword in cmd for keyword in ["/dev/mem", "/proc/kcore", "gdb", "strace", "ptrace"]):
                suspects.append((proc.info['pid'], proc.info['name'], cmd))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspects

def monitor_integrity():
    baseline = {}
    for f in PROTECTED_BINARIES:
        h = sha256sum(f)
        if h:
            baseline[f] = h

    while True:
        for f in PROTECTED_BINARIES:
            current = sha256sum(f)
            if not current:
                continue
            if baseline[f] != current:
                log_alert(f"Firmware tamper detected in {f}")
        suspects = get_suspicious_processes()
        for pid, name, cmd in suspects:
            log_alert(f"Suspicious process detected (PID {pid}, {name}): {cmd}")
        time.sleep(15)

def main():
    print("[*] Firmware Memory Shield activated. Monitoring memory regions and protected binaries...")
    monitor_integrity()

if __name__ == "__main__":
    main()
