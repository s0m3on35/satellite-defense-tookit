#!/usr/bin/env python3
# Ruta: modules/c2/agent_fingerprint_logger.py

import platform
import socket
import json
import psutil
import uuid
import os
import hashlib
import requests
import subprocess
from datetime import datetime
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

OUTPUT_FILE = "logs/agent_fingerprints.json"
EXPORT_STIX_FILE = "results/stix_fingerprint_bundle.json"
ENCRYPTED_BACKUP_FILE = "results/fingerprint_backup.enc"
ENCRYPTION_KEY_ENV = "FP_AES_KEY"

def get_geoip():
    try:
        r = requests.get("https://ipinfo.io/json", timeout=5)
        data = r.json()
        return {
            "public_ip": data.get("ip"),
            "hostname_ext": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "loc": data.get("loc"),
            "org": data.get("org"),
            "asn": data.get("org", "").split(" ")[0] if "org" in data else "unknown"
        }
    except:
        return {}

def get_mac_vendors():
    vendors = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                mac = addr.address
                vendor = lookup_mac_vendor(mac)
                vendors[iface] = {"mac": mac, "vendor": vendor}
    return vendors

def lookup_mac_vendor(mac):
    try:
        prefix = mac.upper().replace(":", "")[:6]
        oui_url = f"https://api.macvendors.com/{prefix}"
        resp = requests.get(oui_url, timeout=3)
        return resp.text.strip()
    except:
        return "unknown"

def get_process_snapshot():
    return sorted(set(p.name() for p in psutil.process_iter()))

def detect_virtualization():
    try:
        output = subprocess.check_output("systemd-detect-virt", stderr=subprocess.DEVNULL).decode().strip()
        return output if output else "none"
    except:
        return "unknown"

def get_fingerprint():
    geo = get_geoip()
    fingerprint = {
        "agent_id": str(uuid.uuid4()),
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "cpu_cores": psutil.cpu_count(logical=True),
        "cpu_info": platform.processor(),
        "mem_total_mb": int(psutil.virtual_memory().total / 1024 / 1024),
        "disk_total_gb": round(psutil.disk_usage('/').total / (1024 ** 3), 2),
        "network_ifaces": list(psutil.net_if_addrs().keys()),
        "virtualization": detect_virtualization(),
        "mac_vendors": get_mac_vendors(),
        "processes": get_process_snapshot(),
        "geoip": geo,
        "timestamp": datetime.utcnow().isoformat()
    }

    raw_data = json.dumps(fingerprint, sort_keys=True).encode()
    fingerprint["fingerprint_hash"] = hashlib.sha256(raw_data).hexdigest()
    return fingerprint

def save_fingerprint(fp_data, out_file=OUTPUT_FILE):
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    if os.path.exists(out_file):
        with open(out_file, "r") as f:
            try:
                existing = json.load(f)
                if not isinstance(existing, list):
                    existing = [existing]
            except:
                existing = []
    else:
        existing = []

    existing.append(fp_data)
    with open(out_file, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"[+] Agent fingerprint saved to {out_file}")

def export_to_stix(fp_data, stix_file=EXPORT_STIX_FILE):
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": [
            {
                "type": "observed-data",
                "id": "observed-data--" + str(uuid.uuid4()),
                "created": datetime.utcnow().isoformat(),
                "modified": datetime.utcnow().isoformat(),
                "first_observed": fp_data["timestamp"],
                "last_observed": fp_data["timestamp"],
                "number_observed": 1,
                "object_refs": [],
                "x_satellite-fingerprint": fp_data
            }
        ]
    }

    os.makedirs(os.path.dirname(stix_file), exist_ok=True)
    with open(stix_file, "w") as f:
        json.dump(stix_bundle, f, indent=2)
    print(f"[+] STIX fingerprint bundle exported to {stix_file}")

def encrypt_backup(fp_data, enc_file=ENCRYPTED_BACKUP_FILE):
    key = os.getenv(ENCRYPTION_KEY_ENV)
    if not key:
        print(f"[!] Skipping encrypted backup: No {ENCRYPTION_KEY_ENV} set")
        return

    try:
        key_bytes = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        data_bytes = json.dumps(fp_data).encode()
        ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
        payload = cipher.iv + ciphertext

        with open(enc_file, "wb") as f:
            f.write(payload)
        print(f"[+] Encrypted fingerprint backup saved to {enc_file}")
    except Exception as e:
        print(f"[!] Failed to encrypt backup: {e}")

if __name__ == "__main__":
    fp = get_fingerprint()
    save_fingerprint(fp)
    export_to_stix(fp)
    encrypt_backup(fp)
