#!/usr/bin/env python3
# Path: modules/c2/agent_commander.py

import os
import json
import argparse
import datetime
import base64
import hashlib
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from getpass import getpass
from uuid import uuid4

AGENT_PATH = "recon/agent_inventory.json"
QUEUE_DIR = "c2/queues"
LOG_DIR = "results"
STIX_FILE = os.path.join(LOG_DIR, "stix_c2_export.json")
KEY_ENV = "C2_AES_KEY"

os.makedirs(QUEUE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

def load_agents():
    if not os.path.exists(AGENT_PATH):
        return {}
    with open(AGENT_PATH, "r") as f:
        return json.load(f)

def list_agents(agents):
    print("\n[+] Available Agents:")
    for idx, (agent_id, data) in enumerate(agents.items(), 1):
        ip = data.get("ip", "unknown")
        osinfo = data.get("os", "unknown")
        mesh = data.get("mesh", "none")
        tags = data.get("tags", [])
        print(f" {idx}. {agent_id} | IP: {ip} | OS: {osinfo} | Mesh: {mesh} | Tags: {', '.join(tags)}")

def encrypt_command(command, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(command.encode(), AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode()

def hash_command(command):
    return hashlib.sha256(command.encode()).hexdigest()

def write_command(agent, command, original_cmd, encrypted=False, chaining=False):
    queue_file = os.path.join(QUEUE_DIR, f"{agent}.queue")
    with open(queue_file, "a") as f:
        f.write(command + "\n")

    log_entry = {
        "uuid": str(uuid4()),
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "agent": agent,
        "encrypted": encrypted,
        "command_hash": hash_command(original_cmd),
        "raw_command": "[ENCRYPTED]" if encrypted else original_cmd,
        "hostname": socket.gethostname(),
        "copilot_chain": chaining,
    }

    # Write JSONL command log
    log_file = os.path.join(LOG_DIR, f"c2_commands_{datetime.datetime.utcnow().strftime('%Y%m%d')}.jsonl")
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    # STIX-lite export (indicator-type)
    stix_object = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid4()}",
        "created": datetime.datetime.utcnow().isoformat() + "Z",
        "modified": datetime.datetime.utcnow().isoformat() + "Z",
        "name": f"C2 Command to {agent}",
        "pattern": f"[command:hashes.'SHA-256' = '{hash_command(original_cmd)}']",
        "pattern_type": "stix",
        "valid_from": datetime.datetime.utcnow().isoformat() + "Z"
    }
    with open(STIX_FILE, "a") as f:
        f.write(json.dumps(stix_object) + "\n")

def check_agent_availability(agent_id, agents):
    if agent_id not in agents:
        print(f"[!] Agent '{agent_id}' not found.")
        return False
    return True

def main():
    parser = argparse.ArgumentParser(description="Send command to C2 agent with optional encryption and chaining")
    parser.add_argument("--agent", help="Agent ID (from inventory)")
    parser.add_argument("--cmd", help="Command to execute on agent")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt command with AES (CBC)")
    parser.add_argument("--list", action="store_true", help="List agents in inventory")
    parser.add_argument("--chain", action="store_true", help="Enable Copilot post-ex chaining logic")

    args = parser.parse_args()
    agents = load_agents()

    if args.list:
        if not agents:
            print("[!] No agents found in inventory.")
            return
        list_agents(agents)
        return

    if not args.agent or not args.cmd:
        print("[!] Both --agent and --cmd are required unless using --list.")
        return

    if not check_agent_availability(args.agent, agents):
        return

    final_cmd = args.cmd
    encrypted = False

    if args.encrypt:
        key = os.environ.get(KEY_ENV)
        if not key:
            key = getpass(f"Enter AES key for encryption (or set env {KEY_ENV}): ")
        final_cmd = encrypt_command(args.cmd, key)
        encrypted = True

    write_command(
        agent=args.agent,
        command=final_cmd,
        original_cmd=args.cmd,
        encrypted=encrypted,
        chaining=args.chain
    )

    print(f"[+] Command successfully sent to agent '{args.agent}'")
    if args.chain:
        print("    └─ Copilot chaining enabled")

if __name__ == "__main__":
    main()
