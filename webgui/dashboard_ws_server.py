#!/usr/bin/env python3
# Path: webgui/dashboard_ws_server.py

import asyncio
import websockets
import json
import os
import logging
import hashlib
from datetime import datetime
from pathlib import Path

# Configuration
CONFIG = {
    "host": "0.0.0.0",
    "port": 8765,
    "log_dir": "logs/dashboard",
    "stix_file": "results/stix_yara_bundle.json",
    "telemetry_file": "results/telemetry_feed.json",
    "forensic_file": "results/forensics_report.json",
    "auth_token": os.getenv("SATDEF_WS_TOKEN"),
    "debug": os.getenv("SATDEF_WS_DEBUG") == "1",
    "stream_interval": 5
}

Path(CONFIG["log_dir"]).mkdir(parents=True, exist_ok=True)
LOG_FILE = os.path.join(CONFIG["log_dir"], "dashboard_stream.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

connected_clients = set()
auth_failures = {}

def utc():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def color(msg, status="info"):
    if not os.isatty(1): return msg
    colors = {"info": "\033[94m", "warn": "\033[93m", "fail": "\033[91m", "ok": "\033[92m", "end": "\033[0m"}
    return f"{colors.get(status, '')}{msg}{colors['end']}"

async def authenticate(websocket):
    if not CONFIG["auth_token"]:
        return True
    try:
        auth_msg = await asyncio.wait_for(websocket.recv(), timeout=5)
        data = json.loads(auth_msg)
        if data.get("auth") == CONFIG["auth_token"]:
            return True
        ip = websocket.remote_address[0]
        auth_failures[ip] = auth_failures.get(ip, 0) + 1
        logging.warning(f"[AUTH] Failed attempt from {ip} ({auth_failures[ip]}x)")
    except Exception as e:
        logging.warning(f"[AUTH] Exception: {e}")
    return False

async def broadcast_to_all(msg):
    dead = set()
    for client in connected_clients:
        try:
            await client.send(msg)
            if CONFIG["debug"]:
                logging.info(f"[→] Sent to {client.remote_address}")
        except websockets.exceptions.ConnectionClosed:
            dead.add(client)
    connected_clients.difference_update(dead)

async def log_event(payload, sender=None):
    try:
        data = json.loads(payload)
        msg_type = data.get("type", "event")
        content = data.get("message", "")
        ts = utc()
        event_id = hashlib.sha256(f"{msg_type}:{content}:{ts}".encode()).hexdigest()[:10]
        logline = f"[{ts}] {msg_type} [{event_id}]: {content}"
        logging.info(logline)
        print(color(f"[{ts}] {msg_type.upper():>8} → {content}", "ok"))
        data["timestamp"] = ts
        data["id"] = event_id
        return json.dumps(data)
    except Exception as e:
        logging.warning(f"[!] Bad message from {sender}: {e}")
        return None

async def stream_file(path, stream_type, interval):
    last_hash = ""
    while True:
        try:
            if os.path.exists(path):
                with open(path) as f:
                    raw = f.read()
                    hash_now = hashlib.md5(raw.encode()).hexdigest()
                    if hash_now != last_hash:
                        last_hash = hash_now
                        msg = json.dumps({
                            "type": stream_type,
                            "timestamp": utc(),
                            "data": json.loads(raw)
                        })
                        await broadcast_to_all(msg)
        except Exception as e:
            logging.error(f"[{stream_type.upper()}] Stream error: {e}")
        await asyncio.sleep(interval)

async def heartbeat():
    while True:
        ping = json.dumps({"type": "ping", "timestamp": utc()})
        await broadcast_to_all(ping)
        await asyncio.sleep(10)

async def ws_handler(websocket, path):
    client_ip = websocket.remote_address[0]
    logging.info(f"[+] New client: {client_ip}")
    if not await authenticate(websocket):
        await websocket.send(json.dumps({"error": "unauthorized"}))
        await websocket.close()
        return

    connected_clients.add(websocket)
    print(color(f"[✓] Client connected: {client_ip}", "ok"))
    try:
        async for message in websocket:
            data = await log_event(message, client_ip)
            if data:
                await broadcast_to_all(data)
    except websockets.exceptions.ConnectionClosed:
        print(color(f"[-] Disconnected: {client_ip}", "warn"))
    finally:
        connected_clients.discard(websocket)

async def main():
    print(color(f"\n[WS] Satellite Dashboard running @ ws://{CONFIG['host']}:{CONFIG['port']}\n", "info"))
    server = await websockets.serve(ws_handler, CONFIG["host"], CONFIG["port"])
    await asyncio.gather(
        server.wait_closed(),
        stream_file(CONFIG["stix_file"], "stix", CONFIG["stream_interval"]),
        stream_file(CONFIG["forensic_file"], "forensics", CONFIG["stream_interval"]),
        stream_file(CONFIG["telemetry_file"], "telemetry", CONFIG["stream_interval"]),
        heartbeat()
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(color("[!] Shutdown initiated by user", "fail"))
