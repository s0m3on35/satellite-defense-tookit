#!/usr/bin/env python3
# Ruta: modules/c2/agent_commander.py

import os
import json
import argparse
import datetime
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from getpass import getpass

AGENT_PATH = "recon/agent_inventory.json"
QUEUE_DIR = "c2/queues"
LOG_DIR = "results"
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
    for idx, (agent, data) in enumerate(agents.items(), 1):
        ip = data.get("ip", "unknown")
        osinfo = data.get("os", "unknown")
        print(f" {idx}. {agent} - {ip} - {osinfo}")

def encrypt_command(command, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(command.encode(), AES.block_size))
    iv = cipher.iv
    encrypted = base64.b64encode(iv + ct_bytes).decode()
    return encrypted

def hash_command(command):
    return hashlib.sha256(command.encode()).hexdigest()

def write_command(agent, command, original_cmd, encrypted=False):
    queue_file = os.path.join(QUEUE_DIR, f"{agent}.queue")
    with open(queue_file, "a") as f:
        f.write(command + "\n")

    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "agent": agent,
        "encrypted": encrypted,
        "command_hash": hash_command(original_cmd),
        "raw_command": "[ENCRYPTED]" if encrypted else original_cmd
    }

    log_file = os.path.join(LOG_DIR, f"c2_commands_{datetime.datetime.utcnow().strftime('%Y%m%d')}.jsonl")
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def main():
    parser = argparse.ArgumentParser(description="Send command to C2 agent")
    parser.add_argument("--agent", help="Agent ID (from inventory)")
    parser.add_argument("--cmd", help="Command to execute")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt command with AES")
    parser.add_argument("--list", action="store_true", help="List agents")

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

    if args.agent not in agents:
        print(f"[!] Agent '{args.agent}' not found.")
        return

    final_cmd = args.cmd
    encrypted = False

    if args.encrypt:
        key = os.environ.get(KEY_ENV)
        if not key:
            key = getpass(f"Enter AES key for encryption (or set env {KEY_ENV}): ")
        final_cmd = encrypt_command(args.cmd, key)
        encrypted = True

    write_command(args.agent, final_cmd, args.cmd, encrypted=encrypted)
    print(f"[+] Command sent to agent '{args.agent}' successfully.")

if __name__ == "__main__":
    main()
