#!/usr/bin/env python3
# Route: modules/defense/firmware_rollback_protector.py
# Description: Prevents firmware rollback by enforcing version nonce tracking

import json
import os
from datetime import datetime
import subprocess

MANIFEST_PATH = "/firmware/update_manifest.json"
VERSION_LEDGER = "/etc/sdt_firmware_ledger.json"
ALERT_LOG = "/var/log/sdt_rollback_protector.log"

def log_alert(message):
    timestamp = datetime.utcnow().isoformat()
    alert = f"{timestamp} - {message}"
    with open(ALERT_LOG, "a") as f:
        f.write(alert + "\n")
    subprocess.call(["logger", "-p", "auth.crit", alert])

def read_manifest():
    if not os.path.exists(MANIFEST_PATH):
        log_alert("Update manifest missing.")
        return None
    with open(MANIFEST_PATH, 'r') as f:
        return json.load(f)

def read_ledger():
    if not os.path.exists(VERSION_LEDGER):
        return {"last_nonce": 0}
    with open(VERSION_LEDGER, 'r') as f:
        return json.load(f)

def write_ledger(new_nonce):
    with open(VERSION_LEDGER, 'w') as f:
        json.dump({"last_nonce": new_nonce}, f)

def check_rollback():
    manifest = read_manifest()
    if not manifest:
        return False

    update_nonce = int(manifest.get("version_nonce", 0))
    current_ledger = read_ledger()
    last_nonce = int(current_ledger.get("last_nonce", 0))

    if update_nonce <= last_nonce:
        log_alert(f"Rollback attempt detected: nonce {update_nonce} <= {last_nonce}")
        return False

    write_ledger(update_nonce)
    return True

def main():
    print("[*] Checking for firmware rollback protection...")
    if check_rollback():
        print("[+] Update nonce accepted. Proceeding with update.")
    else:
        print("[!] Firmware update blocked due to rollback protection policy.")

if __name__ == "__main__":
    main()
