#!/usr/bin/env python3
# Path: webgui/dashboard_ws_server.py
# Description: WebSocket server for the Satellite Defense Toolkit live dashboard

import asyncio
import websockets
import json
import os
import logging
import hashlib
from datetime import datetime
from pathlib import Path

# === Configuration ===
CONFIG = {
    "host": "0.0.0.0",
    "port": 8765,
    "log_dir": "logs/dashboard",
    "stix_file": "results/stix_yara_bundle.json",
    "telemetry_file": "results/telemetry_feed.json",
    "forensic_file": "results/forensics_report.json",
    "auth_token": os.getenv("SATDEF_WS_TOKEN"),
    "debug": os.getenv("SATDEF_WS_DEBUG") == "1",
    "stream_interval": 5,
    "heartbeat_interval": 10
}

# Ensure directories exist
Path(CONFIG["log_dir"]).mkdir(parents=True, exist_ok=True)
Path("results").mkdir(parents=True, exist_ok=True)
LOG_FILE = os.path.join(CONFIG["log_dir"], "dashboard_stream.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

connected_clients = set()
auth_failures = {}

# === Utilities ===

def utc():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def color(msg, level="info"):
    if not os.isatty(1): return msg
    colors = {
        "info": "\033[94m",
        "ok": "\033[92m",
        "warn": "\033[93m",
        "fail": "\033[91m",
        "end": "\033[0m"
    }
    return f"{colors.get(level, '')}{msg}{colors['end']}"

# === Authentication ===

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
        logging.warning(f"[AUTH] Rejected: {ip} (attempt {auth_failures[ip]})")
    except Exception as e:
        logging.warning(f"[AUTH] Exception: {e}")
    return False

# === Broadcast Helpers ===

async def broadcast_to_all(message):
    disconnected = set()
    for client in connected_clients:
        try:
            await client.send(message)
            if CONFIG["debug"]:
                logging.info(f"[→] Sent to {client.remote_address}")
        except websockets.exceptions.ConnectionClosed:
            disconnected.add(client)
    connected_clients.difference_update(disconnected)

# === Log Handling ===

async def log_event(payload, sender=None):
    try:
        data = json.loads(payload)
        msg_type = data.get("type", "event")
        content = data.get("message", "")
        ts = utc()
        event_id = hashlib.sha256(f"{msg_type}:{content}:{ts}".encode()).hexdigest()[:10]
        log_line = f"[{ts}] {msg_type} [{event_id}]: {content}"
        logging.info(log_line)
        print(color(f"[{ts}] {msg_type.upper():>8} → {content}", "ok"))
        data["timestamp"] = ts
        data["id"] = event_id
        return json.dumps(data)
    except Exception as e:
        logging.warning(f"[!] Malformed payload from {sender}: {e}")
        return None

# === Data Streamers ===

async def stream_file(path, stream_type, interval):
    last_hash = ""
    while True:
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    raw = f.read()
                    current_hash = hashlib.md5(raw.encode()).hexdigest()
                    if current_hash != last_hash:
                        last_hash = current_hash
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
        await asyncio.sleep(CONFIG["heartbeat_interval"])

# === WebSocket Handler ===

async def ws_handler(websocket, path):
    ip = websocket.remote_address[0]
    logging.info(f"[+] WebSocket connection from {ip}")

    if not await authenticate(websocket):
        await websocket.send(json.dumps({"error": "unauthorized"}))
        await websocket.close()
        return

    connected_clients.add(websocket)
    print(color(f"[✓] Client authenticated: {ip}", "ok"))

    try:
        async for message in websocket:
            response = await log_event(message, ip)
            if response:
                await broadcast_to_all(response)
    except websockets.exceptions.ConnectionClosed:
        print(color(f"[-] Disconnected: {ip}", "warn"))
    finally:
        connected_clients.discard(websocket)

# === Main Entry Point ===

async def main():
    print(color(f"\n[WS] Dashboard active @ ws://{CONFIG['host']}:{CONFIG['port']}\n", "info"))
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
        print(color("[!] Shutdown signal received. WebSocket server exiting.", "fail"))
