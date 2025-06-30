#!/usr/bin/env python3

import argparse
import hashlib
import os
import time
import json
import logging
import yaml
import asyncio
import websockets
from datetime import datetime

CONFIG_PATH = "config/config.yaml"
LOG_FILE = "logs/firmware_watcher.log"
FIRMWARE_PATH = "test_firmware.bin"
ALERT_FILE = "results/firmware_alert.json"
WEBSOCKET_URL = "ws://localhost:8765"
AGENT_ID = "firmware_watcher"

def compute_hash(filepath, algo='sha256'):
    h = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def push_alert(alert):
    os.makedirs("results", exist_ok=True)
    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=2)
    try:
        asyncio.run(websocket_notify(alert))
    except Exception:
        pass

async def websocket_notify(alert):
    async with websockets.connect(WEBSOCKET_URL) as ws:
        await ws.send(json.dumps({
            "agent": AGENT_ID,
            "type": "firmware",
            "alert": alert
        }))

def auto_generate_firmware(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(os.urandom(512))
    return compute_hash(path)

def auto_generate_config():
    os.makedirs("config", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    hash_value = auto_generate_firmware(FIRMWARE_PATH)
    cfg = {
        "firmware_path": FIRMWARE_PATH,
        "expected_hash": hash_value,
        "interval": 10,
        "hash_algo": "sha256"
    }
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f)
    return cfg

def setup_logging():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def sandbox_diff(firmware_path):
    with open(firmware_path, 'rb') as f:
        data = f.read()
    patterns = [b'\x90\x90', b'root', b'\x7fELF']
    matches = [p.hex() for p in patterns if p in data]
    return matches

def monitor_firmware(file_path, expected_hash, interval, algo):
    logging.info(f"Monitoring firmware at {file_path} every {interval}s")
    while True:
        if not os.path.exists(file_path):
            logging.warning("Firmware not found")
        else:
            current_hash = compute_hash(file_path, algo)
            logging.info(f"{algo.upper()} Hash: {current_hash}")
            if current_hash != expected_hash:
                diff_patterns = sandbox_diff(file_path)
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "agent": AGENT_ID,
                    "file": file_path,
                    "expected": expected_hash,
                    "found": current_hash,
                    "diff": diff_patterns,
                    "alert": "HASH_MISMATCH"
                }
                logging.error("Firmware hash mismatch")
                push_alert(alert)
                break
        time.sleep(interval)

def main():
    setup_logging()
    if not os.path.exists(CONFIG_PATH):
        config = auto_generate_config()
    else:
        with open(CONFIG_PATH, 'r') as f:
            config = yaml.safe_load(f)
    monitor_firmware(
        config['firmware_path'],
        config['expected_hash'],
        config.get('interval', 10),
        config.get('hash_algo', 'sha256')
    )

if __name__ == "__main__":
    main()
