#!/usr/bin/env python3
# Ruta: webgui/dashboard_ws_server.py

import asyncio
import websockets
import json
import os
import hashlib
import logging
from datetime import datetime

# Paths
LOG_DIR = "logs/dashboard"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "dashboard_stream.log")
STIX_FILE = "results/stix_yara_bundle.json"
FORENSIC_LOG = "results/forensics_report.json"
TELEMETRY_LOG = "results/telemetry_feed.json"

# Auth & Config
AUTH_TOKEN = os.environ.get("SATDEF_WS_TOKEN")
DEBUG = os.environ.get("SATDEF_WS_DEBUG") == "1"

# State
connected_clients = set()
auth_failures = {}

# Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)

def utc_timestamp():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

async def log_handler(message, client=None):
    try:
        data = json.loads(message)
        msg_type = data.get("type", "event")
        content = data.get("message", "")
        event_id = hashlib.sha256(f"{msg_type}:{content}:{utc_timestamp()}".encode()).hexdigest()[:10]
        log_entry = f"[{utc_timestamp()}] {msg_type} [{event_id}]: {content}"
        logging.info(log_entry)
        data["timestamp"] = utc_timestamp()
        data["id"] = event_id
        return data
    except json.JSONDecodeError:
        logging.warning(f"Invalid JSON from {client}: {message}")
        return None

async def broadcast_json_from_file(filepath, datatype, interval=5):
    last_sent_hash = ""
    while True:
        try:
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    data = json.load(f)
                    payload = json.dumps({
                        "type": datatype,
                        "timestamp": utc_timestamp(),
                        "data": data
                    })
                    payload_hash = hashlib.md5(payload.encode()).hexdigest()
                    if payload_hash != last_sent_hash:
                        await broadcast_to_all(payload)
                        last_sent_hash = payload_hash
        except Exception as e:
            logging.error(f"[{datatype.upper()} STREAM] Error: {e}")
        await asyncio.sleep(interval)

async def broadcast_to_all(message):
    disconnected = set()
    for client in connected_clients:
        try:
            await client.send(message)
            if DEBUG:
                logging.info(f"[→] Sent to {client.remote_address}: {message[:80]}")
        except websockets.exceptions.ConnectionClosed:
            disconnected.add(client)
    connected_clients.difference_update(disconnected)

async def authenticate(websocket):
    if not AUTH_TOKEN:
        return True
    try:
        auth_msg = await asyncio.wait_for(websocket.recv(), timeout=5)
        auth_data = json.loads(auth_msg)
        token = auth_data.get("auth")
        if token == AUTH_TOKEN:
            return True
        ip = websocket.remote_address[0]
        auth_failures[ip] = auth_failures.get(ip, 0) + 1
        logging.warning(f"[!] Invalid token from {ip} (attempt {auth_failures[ip]})")
    except Exception as e:
        logging.warning(f"[!] Auth exception: {e}")
    return False

async def handler(websocket, path):
    client_ip = websocket.remote_address[0]
    logging.info(f"[+] Connection from: {client_ip}")

    if not await authenticate(websocket):
        await websocket.send(json.dumps({"error": "unauthorized"}))
        await websocket.close()
        logging.info(f"[×] Unauthorized connection closed: {client_ip}")
        return

    connected_clients.add(websocket)
    logging.info(f"[✓] WebSocket connected: {client_ip}")
    try:
        async for message in websocket:
            data = await log_handler(message, client_ip)
            if data:
                await broadcast_to_all(json.dumps(data))
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"[-] Client disconnected: {client_ip}")
    finally:
        connected_clients.discard(websocket)

async def main():
    print("[WS Server] Satellite Defense WebSocket running on ws://0.0.0.0:8765")
    server = await websockets.serve(handler, "0.0.0.0", 8765)

    await asyncio.gather(
        server.wait_closed(),
        broadcast_json_from_file(STIX_FILE, "stix"),
        broadcast_json_from_file(FORENSIC_LOG, "forensics"),
        broadcast_json_from_file(TELEMETRY_LOG, "telemetry")
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Shutdown requested. Exiting.")
