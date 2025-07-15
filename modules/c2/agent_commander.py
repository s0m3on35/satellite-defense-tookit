#!/usr/bin/env python3
# modules/c2/agent_commander.py

import os
import json
import argparse
import base64
import hashlib
import datetime
import socket
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pathlib import Path
import random
import string

AGENT_FILE = "recon/agent_inventory.json"
QUEUE_DIR = "c2/queues"
LOG_DIR = "results"
STIX_FILE = os.path.join(LOG_DIR, "stix_c2_commands.json")
KEY_ENV = "C2_AES_KEY"
MAX_QUEUE_SIZE = 50

Path(QUEUE_DIR).mkdir(parents=True, exist_ok=True)
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

def gen_uuid():
    return str(uuid.uuid4())

def now_iso():
    return datetime.datetime.utcnow().isoformat()

def random_id(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def load_agents():
    if not os.path.exists(AGENT_FILE):
        return {}
    with open(AGENT_FILE, "r") as f:
        return json.load(f)

def list_agents(agents):
    for i, (k, v) in enumerate(agents.items(), 1):
        print(f"{i:02d}. {k} - {v.get('ip','N/A')} - {v.get('os','N/A')}")

def base64_encode(data):
    return base64.b64encode(data.encode()).decode()

def encrypt_command(command, key):
    k = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(k, AES.MODE_CBC)
    ct = cipher.encrypt(pad(command.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct).decode()

def write_queue(agent_id, cmd):
    queue_path = os.path.join(QUEUE_DIR, f"{agent_id}.queue")
    with open(queue_path, "a") as f:
        f.write(cmd + "\n")
    # Limit queue size
    with open(queue_path, "r") as f:
        lines = f.readlines()
    if len(lines) > MAX_QUEUE_SIZE:
        with open(queue_path, "w") as f:
            f.writelines(lines[-MAX_QUEUE_SIZE:])

def log_command(agent, cmd_raw, cmd_enc, encrypted):
    ts = now_iso()
    daylog = os.path.join(LOG_DIR, f"c2_log_{datetime.datetime.utcnow().strftime('%Y%m%d')}.jsonl")
    entry = {
        "id": gen_uuid(),
        "timestamp": ts,
        "agent": agent,
        "encrypted": encrypted,
        "hash": hashlib.sha256(cmd_raw.encode()).hexdigest(),
        "command": cmd_enc if encrypted else cmd_raw
    }
    with open(daylog, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry

def append_stix(entry):
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{entry['id']}",
        "created": entry["timestamp"],
        "modified": entry["timestamp"],
        "labels": ["c2-tasking"],
        "pattern": "[command:value = '{}']".format(entry["hash"]),
        "pattern_type": "stix",
        "valid_from": entry["timestamp"],
        "description": f"C2 command sent to agent {entry['agent']}"
    }
    observed = {
        "type": "observed-data",
        "id": f"observed-data--{entry['id']}",
        "created": entry["timestamp"],
        "modified": entry["timestamp"],
        "first_observed": entry["timestamp"],
        "last_observed": entry["timestamp"],
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "command",
                "value": entry["command"]
            }
        }
    }
    bundle = {
        "type": "bundle",
        "id": f"bundle--{gen_uuid()}",
        "spec_version": "2.1",
        "objects": [indicator, observed]
    }
    with open(STIX_FILE, "a") as f:
        f.write(json.dumps(bundle) + "\n")

def discover_self():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"

def main():
    parser = argparse.ArgumentParser(description="C2 Command Dispatcher")
    parser.add_argument("--agent", help="Agent ID to task")
    parser.add_argument("--cmd", help="Command to send")
    parser.add_argument("--list", action="store_true", help="List known agents")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt using AES")
    parser.add_argument("--stix", action="store_true", help="Log STIX bundle")
    args = parser.parse_args()

    agents = load_agents()
    if args.list:
        if not agents:
            print("No agents found.")
            return
        list_agents(agents)
        return

    if not args.agent or not args.cmd:
        print("Agent and command are required unless using --list.")
        return

    if args.agent not in agents:
        print(f"Agent '{args.agent}' not found.")
        return

    raw_cmd = args.cmd
    final_cmd = raw_cmd
    encrypted = False

    if args.encrypt:
        key = os.environ.get(KEY_ENV)
        if not key:
            from getpass import getpass
            key = getpass("Enter AES encryption key: ")
        final_cmd = encrypt_command(raw_cmd, key)
        encrypted = True

    write_queue(args.agent, final_cmd)
    log_entry = log_command(args.agent, raw_cmd, final_cmd, encrypted)

    if args.stix:
        append_stix(log_entry)

    print(f"[+] Task queued to agent: {args.agent} ({'encrypted' if encrypted else 'plain'})")

if __name__ == "__main__":
    main()
