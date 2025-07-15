#!/usr/bin/env python3
# Ruta: modules/c2/agent_commander.py

import os
import json
import argparse
import datetime
import base64
import hashlib
import socket
import subprocess
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
from urllib.parse import quote

AGENT_PATH = "recon/agent_inventory.json"
QUEUE_DIR = "c2/queues"
LOG_DIR = "results"
KEY_ENV = "C2_AES_KEY"
HMAC_ENV = "C2_HMAC_KEY"
TOR_SOCKS_PROXY = "127.0.0.1:9050"
DNS_TUNNEL_DOMAIN = "agentcmd.example.com"

os.makedirs(QUEUE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

def load_agents():
    if not os.path.exists(AGENT_PATH):
        return {}
    with open(AGENT_PATH, "r") as f:
        return json.load(f)

def hash_command(command):
    return hashlib.sha256(command.encode()).hexdigest()

def encrypt_command(command, key, hmac_key=None):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(command.encode(), AES.block_size))
    iv = cipher.iv
    payload = iv + ct_bytes
    if hmac_key:
        h = HMAC.new(hmac_key.encode(), digestmod=SHA256)
        h.update(payload)
        payload += h.digest()
    return base64.b64encode(payload).decode()

def write_queue(agent, command):
    queue_file = os.path.join(QUEUE_DIR, f"{agent}.queue")
    with open(queue_file, "a") as f:
        f.write(command + "\n")

def log_command(agent, cmd, encrypted, fallback_used):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "agent": agent,
        "encrypted": encrypted,
        "fallback": fallback_used,
        "command_hash": hash_command(cmd),
        "command": "[ENCRYPTED]" if encrypted else cmd
    }
    logfile = os.path.join(LOG_DIR, f"c2_commands_{datetime.datetime.utcnow().strftime('%Y%m%d')}.jsonl")
    with open(logfile, "a") as f:
        f.write(json.dumps(entry) + "\n")

def export_stix(agent, cmd, fallback):
    bundle = {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(agent.encode()).hexdigest()}",
        "objects": [
            {
                "type": "command-control",
                "id": f"command-control--{hash_command(cmd)}",
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "agent_ref": agent,
                "command": cmd,
                "fallback_used": fallback
            }
        ]
    }
    stix_file = os.path.join(LOG_DIR, f"stix_command_{agent}.json")
    with open(stix_file, "w") as f:
        json.dump(bundle, f, indent=2)

def resolve_tailscale_ip(agent_id):
    try:
        result = subprocess.check_output(["tailscale", "status", "--json"], text=True)
        status = json.loads(result)
        for peer in status.get("Peer", {}).values():
            if agent_id in peer.get("HostName", ""):
                return peer.get("TailscaleIPs", [])[0]
    except Exception:
        return None

def send_over_tor(agent, encoded_cmd):
    try:
        agent_onion = agent if ".onion" in agent else f"{agent}.onion"
        curl_cmd = [
            "curl", "-x", f"socks5h://{TOR_SOCKS_PROXY}",
            f"http://{agent_onion}/receive?c={quote(encoded_cmd)}"
        ]
        subprocess.run(curl_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def send_over_rf(agent, encoded_cmd):
    rf_file = f"/tmp/cmd_{agent}.bin"
    with open(rf_file, "wb") as f:
        f.write(base64.b64decode(encoded_cmd))
    subprocess.run(["hackrf_transfer", "-t", rf_file, "-f", "433920000", "-x", "20", "-s", "2000000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.remove(rf_file)

def send_over_dead_drop(agent, encoded_cmd):
    path = f"/var/dropzone/{agent}.cmd"
    with open(path, "w") as f:
        f.write(encoded_cmd)

def send_over_dns(agent, encoded_cmd):
    label = encoded_cmd[:50].replace("=", "")  # keep it short
    fqdn = f"{label}.{agent}.{DNS_TUNNEL_DOMAIN}"
    try:
        socket.gethostbyname(fqdn)
    except:
        pass

def send_command(agent, cmd, encrypted=False, hmac=False, fallback="lan"):
    fallback_chain = fallback.split(",")
    key = os.environ.get(KEY_ENV) if encrypted else None
    hmac_key = os.environ.get(HMAC_ENV) if hmac else None
    encoded_cmd = encrypt_command(cmd, key, hmac_key) if encrypted else cmd

    sent = False
    for method in fallback_chain:
        if method == "lan":
            write_queue(agent, encoded_cmd)
            sent = True
        elif method == "tailscale":
            ip = resolve_tailscale_ip(agent)
            if ip:
                subprocess.run(["curl", f"http://{ip}/receive?c={quote(encoded_cmd)}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                sent = True
        elif method == "tor":
            sent = send_over_tor(agent, encoded_cmd)
        elif method == "rf":
            send_over_rf(agent, encoded_cmd)
            sent = True
        elif method == "dead":
            send_over_dead_drop(agent, encoded_cmd)
            sent = True
        elif method == "dns":
            send_over_dns(agent, encoded_cmd)
            sent = True
        if sent:
            break

    log_command(agent, cmd, encrypted, method)
    export_stix(agent, cmd, method)
    print(f"[+] Command sent to '{agent}' via {method.upper()}")

def main():
    parser = argparse.ArgumentParser(description="Satellite Defense Toolkit C2 Commander")
    parser.add_argument("--agent", help="Agent ID")
    parser.add_argument("--cmd", help="Command to execute")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt command using AES")
    parser.add_argument("--hmac", action="store_true", help="HMAC sign command")
    parser.add_argument("--fallback", default="lan,tailscale,tor,rf,dead,dns", help="Fallback methods (comma-separated)")
    parser.add_argument("--list", action="store_true", help="List available agents")

    args = parser.parse_args()
    agents = load_agents()

    if args.list:
        for aid, data in agents.items():
            print(f"{aid}: {data.get('ip', 'N/A')} ({data.get('os', 'unknown')})")
        return

    if not args.agent or not args.cmd:
        print("[!] You must specify both --agent and --cmd (or use --list)")
        return

    if args.agent not in agents:
        print(f"[!] Agent '{args.agent}' not found in inventory.")
        return

    send_command(args.agent, args.cmd, args.encrypt, args.hmac, args.fallback)

if __name__ == "__main__":
    main()
