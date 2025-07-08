#!/usr/bin/env python3
# Route: modules/defense/kernel_module_guard.py
# Description: Monitors and alerts on unauthorized kernel module loads, hidden modules, and integrity violations

import os
import hashlib
import time
from datetime import datetime
import subprocess

WHITELISTED_MODULES_FILE = "/etc/sdt_whitelisted_modules.txt"
LOG_FILE = "/var/log/sdt_kernel_module_guard.log"
SCAN_INTERVAL = 30  # seconds

def log_alert(msg):
    timestamp = datetime.utcnow().isoformat()
    full = f"{timestamp} - ALERT: {msg}"
    with open(LOG_FILE, "a") as f:
        f.write(full + "\n")
    os.system(f'logger -p auth.crit "{full}"')

def load_whitelisted_modules():
    if not os.path.exists(WHITELISTED_MODULES_FILE):
        return set()
    with open(WHITELISTED_MODULES_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())

def get_loaded_modules():
    try:
        output = subprocess.check_output(["lsmod"]).decode()
        return set(line.split()[0] for line in output.strip().split("\n")[1:])
    except Exception as e:
        log_alert(f"Failed to retrieve loaded modules: {e}")
        return set()

def check_for_hidden_modules():
    try:
        # List modules from sysfs
        sysfs_modules = set(os.listdir("/sys/module"))
        proc_modules = get_loaded_modules()
        hidden = proc_modules - sysfs_modules
        if hidden:
            for mod in hidden:
                log_alert(f"Hidden module detected: {mod}")
    except Exception as e:
        log_alert(f"Error checking hidden modules: {e}")

def monitor_modules():
    whitelisted = load_whitelisted_modules()
    while True:
        loaded = get_loaded_modules()
        for mod in loaded:
            if mod not in whitelisted:
                log_alert(f"Unauthorized kernel module loaded: {mod}")
        check_for_hidden_modules()
        time.sleep(SCAN_INTERVAL)

def main():
    print("[*] Kernel Module Guard active.")
    monitor_modules()

if __name__ == "__main__":
    main()
