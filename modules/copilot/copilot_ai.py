import os
import json
import platform
import socket
import hashlib
import datetime
import argparse
import getpass
import base64
from cryptography.fernet import Fernet

# =Config 
TELEMETRY_PATH = "results/telemetry_anomalies.json"
AGENT_FILE = "recon/agent_inventory.json"
MARKDOWN_PATH = "reports/copilot_summary.md"
JSON_EXPORT_PATH = "reports/copilot_alerts.json"
ENCRYPTION_KEY_PATH = "config/copilot_aes.key"

#Utility Functio
def load_telemetry():
    if not os.path.exists(TELEMETRY_PATH):
        return []
    with open(TELEMETRY_PATH, 'r') as f:
        return json.load(f)

def enrich_alert(alert):
    alert['agent'] = {
        'hostname': socket.gethostname(),
        'ip': socket.gethostbyname(socket.gethostname()),
        'os': platform.system(),
        'user': getpass.getuser()
    }
    alert['mapped_ttp'] = 'T1046'
    alert['kill_chain'] = 'collection'
    return alert

def generate_summary_md(alerts):
    lines = ["# Copilot Summary Report\n"]
    for a in alerts:
        lines.append(f"- **Time**: {a['timestamp']} | **Z**: {a['z_score']:.2f} | **TTP**: {a['mapped_ttp']} | **Host**: {a['agent']['hostname']}")
    return '\n'.join(lines)

def save_report(alerts):
    os.makedirs("reports", exist_ok=True)
    with open(MARKDOWN_PATH, 'w') as f:
        f.write(generate_summary_md(alerts))
    with open(JSON_EXPORT_PATH, 'w') as f:
        json.dump(alerts, f, indent=2)

def load_key():
    if os.path.exists(ENCRYPTION_KEY_PATH):
        with open(ENCRYPTION_KEY_PATH, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(ENCRYPTION_KEY_PATH), exist_ok=True)
    with open(ENCRYPTION_KEY_PATH, 'wb') as f:
        f.write(key)
    return key

def encrypt_file(path):
    key = load_key()
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        encrypted = fernet.encrypt(file.read())
    with open(path + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted)

def interactive_prompt(alerts):
    while True:
        print("\n=== Copilot AI ===")
        print("1. Show summary")
        print("2. Export markdown + JSON")
        print("3. Encrypt for USB export")
        print("4. Exit")
        choice = input("Select> ").strip()

        if choice == '1':
            print(generate_summary_md(alerts))
        elif choice == '2':
            save_report(alerts)
            print("Reports saved to 'reports/'")
        elif choice == '3':
            encrypt_file(JSON_EXPORT_PATH)
            encrypt_file(MARKDOWN_PATH)
            print("Encrypted copies generated.")
        elif choice == '4':
            break
        else:
            print("Invalid selection.")

def main():
    raw_alerts = load_telemetry()
    alerts = [enrich_alert(a) for a in raw_alerts if a.get('alert') == 'ANOMALY_DETECTED']
    interactive_prompt(alerts)

if __name__ == '__main__':
    main()
