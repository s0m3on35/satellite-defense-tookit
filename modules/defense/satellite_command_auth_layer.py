#!/usr/bin/env python3
# Satellite Command Auth Layer - Satellite Defense Toolkit
# Monitors and validates satellite control uplink commands

import os
import json
import time
import hmac
import hashlib
import logging
from datetime import datetime
from stix2 import Bundle, Indicator, ObservedData

# === Configuration ===
CMD_LOG_FILE = "logs/satellite_commands.jsonl"         # Simulated command feed
ALERT_FILE = "webgui/alerts.json"
STIX_OUT = "results/stix/satcmd_auth_alert_bundle.json"
LOG_FILE = "logs/satcmd_auth_layer.log"
SECRET_KEY = b"space-control-secret"
VALID_COMMANDS = ["ACTIVATE_THRUSTER", "DEPLOY_PAYLOAD", "SWITCH_MODE_SAFE", "REBOOT", "PING", "CALIBRATE"]
STEALTH_MODE = False

# === Setup ===
os.makedirs("results/stix", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def hmac_check(command, signature):
    computed = hmac.new(SECRET_KEY, command.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)

def validate_command(cmd_entry):
    command = cmd_entry.get("command", "")
    signature = cmd_entry.get("signature", "")
    timestamp = cmd_entry.get("timestamp", "")
    source = cmd_entry.get("source", "unknown")

    if not hmac_check(command, signature):
        return False, f"Invalid signature for command '{command}' from {source}"
    if command not in VALID_COMMANDS:
        return False, f"Unauthorized command '{command}' attempted from {source}"
    return True, f"Authorized command '{command}' accepted from {source}"

def log_alert(reason, entry):
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "module": "Satellite Command Auth Layer",
        "alert": reason,
        "entry": entry
    }

    if os.path.exists(ALERT_FILE):
        try:
            with open(ALERT_FILE, "r") as f:
                alerts = json.load(f)
        except Exception:
            alerts = []
    else:
        alerts = []

    alerts.append(alert)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    logging.warning(reason)
    export_stix(reason, entry)

def export_stix(reason, entry):
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    command = entry.get("command", "UNKNOWN")
    source = entry.get("source", "unknown")

    indicator = Indicator(
        name="Unauthorized Satellite Command Attempt",
        description=reason,
        pattern=f"[x-satcmd:command = '{command}']",
        valid_from=now,
        labels=["satellite", "command", "auth", "intrusion"]
    )

    observed = ObservedData(
        first_observed=now,
        last_observed=now,
        number_observed=1,
        objects={"0": {
            "type": "x-satcmd",
            "command": command,
            "source": source
        }}
    )

    bundle = Bundle(indicator, observed)
    with open(STIX_OUT, "w") as f:
        f.write(bundle.serialize(pretty=True))

def monitor_commands():
    print("[*] Satellite Command Auth Layer is live.") if not STEALTH_MODE else None
    seen = set()
    while True:
        try:
            with open(CMD_LOG_FILE, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            time.sleep(5)
            continue

        for line in lines[-20:]:
            if line in seen:
                continue
            seen.add(line)
            try:
                entry = json.loads(line)
                valid, msg = validate_command(entry)
                if not valid:
                    log_alert(msg, entry)
                elif not STEALTH_MODE:
                    print(f"[+] {msg}")
            except Exception as e:
                logging.error(f"Parse error: {e}")
        time.sleep(5)

if __name__ == "__main__":
    try:
        monitor_commands()
    except KeyboardInterrupt:
        print("[!] Stopped.")
