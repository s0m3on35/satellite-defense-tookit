# modules/c2/agent_fingerprint_logger.py
import platform
import socket
import json
import psutil
import uuid
import os

def get_fingerprint():
    return {
        "agent_id": str(uuid.uuid4()),
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "arch": platform.machine(),
        "cpu_cores": psutil.cpu_count(logical=True),
        "mem_total_mb": int(psutil.virtual_memory().total / 1024 / 1024),
        "network_ifaces": list(psutil.net_if_addrs().keys())
    }

def save_fingerprint(fp_data, out_file="logs/agent_fingerprints.json"):
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    if os.path.exists(out_file):
        with open(out_file, "r") as f:
            existing = json.load(f)
    else:
        existing = []
    existing.append(fp_data)
    with open(out_file, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"[+] Agent fingerprint saved to {out_file}")

if __name__ == "__main__":
    fp = get_fingerprint()
    save_fingerprint(fp)
