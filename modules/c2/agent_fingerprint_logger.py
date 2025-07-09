#!/usr/bin/env python3
# Ruta: modules/c2/agent_fingerprint_logger.py

import platform
import socket
import json
import psutil
import uuid
import os
import hashlib
from datetime import datetime

OUTPUT_FILE = "logs/agent_fingerprints.json"
EXPORT_STIX_FILE = "results/stix_fingerprint_bundle.json"

def get_fingerprint():
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
        "timestamp": datetime.utcnow().isoformat()
    }

    # Hash fingerprint to create unique short ID
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

if __name__ == "__main__":
    fingerprint = get_fingerprint()
    save_fingerprint(fingerprint)
    export_to_stix(fingerprint)
