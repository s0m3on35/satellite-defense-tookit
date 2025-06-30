import os
import json
import time
import shutil
import tarfile
import zipfile
import argparse
import subprocess
from datetime import datetime

AGENT_ID = "firmware_unpacker"
ALERT_FILE = "webgui/alerts.json"
AGENTS_DB = "webgui/agents.json"
UNPACK_DIR = "firmware/unpacked"
CHAIN_SCRIPTS = [
    "modules/firmware_backdoor_scanner.py",
    "modules/telemetry_lstm_monitor.py",
    "modules/report_builder.py"
]

def log(msg):
    print(f"[UNPACK] {msg}")

def push_alert(msg):
    alert = {
        "agent": AGENT_ID,
        "alert": msg,
        "type": "firmware",
        "timestamp": time.time()
    }
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def register_agent():
    os.makedirs(os.path.dirname(AGENTS_DB), exist_ok=True)
    if not os.path.exists(AGENTS_DB):
        with open(AGENTS_DB, "w") as f:
            json.dump([], f)
    with open(AGENTS_DB, "r") as f:
        agents = json.load(f)
    if AGENT_ID not in [a["id"] for a in agents]:
        agents.append({
            "id": AGENT_ID,
            "type": "firmware",
            "registered": datetime.now().isoformat()
        })
        with open(AGENTS_DB, "w") as f:
            json.dump(agents, f, indent=2)

def unpack_firmware(path):
    os.makedirs(UNPACK_DIR, exist_ok=True)
    base = os.path.basename(path)
    target_dir = os.path.join(UNPACK_DIR, os.path.splitext(base)[0])
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    os.makedirs(target_dir)

    if path.endswith(".zip"):
        with zipfile.ZipFile(path, 'r') as zf:
            zf.extractall(target_dir)
    elif path.endswith(".tar") or path.endswith(".tar.gz") or path.endswith(".tgz"):
        with tarfile.open(path, 'r:*') as tf:
            tf.extractall(target_dir)
    elif path.endswith(".img") or path.endswith(".bin"):
        dd_path = os.path.join(target_dir, "raw_extract")
        os.makedirs(dd_path, exist_ok=True)
        subprocess.run(["binwalk", "--extract", "--directory", dd_path, path])
    else:
        raise ValueError("Unsupported firmware format")

    return target_dir

def chain_scripts(unpacked_dir):
    for script in CHAIN_SCRIPTS:
        subprocess.Popen(["python3", script, "--input", unpacked_dir])

def main():
    parser = argparse.ArgumentParser(description="Firmware Auto-Unpacker")
    parser.add_argument("--firmware", required=True, help="Path to firmware file")
    args = parser.parse_args()

    register_agent()
    log(f"Unpacking firmware: {args.firmware}")
    push_alert("Firmware unpacking started")

    try:
        out_dir = unpack_firmware(args.firmware)
        log(f"Unpacked to: {out_dir}")
        push_alert("Firmware unpacking complete")
        chain_scripts(out_dir)
    except Exception as e:
        log(f"Error: {str(e)}")
        push_alert(f"Unpacking failed: {str(e)}")

if __name__ == "__main__":
    main()
