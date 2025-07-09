#!/usr/bin/env python3
# Ruta: webgui/playback_panel.py
# Descripción: Reproductor de eventos históricos para el dashboard en tiempo real del Satellite Defense Toolkit

import asyncio
import websockets
import json
import os
import argparse
from datetime import datetime

LOG_FILE = "logs/dashboard/dashboard_stream.log"

def parse_log_line(line):
    """
    Extrae y convierte una línea de log en un evento estructurado.
    """
    try:
        # Ejemplo de línea: [2025-07-09T10:22:11] event [abc1234]: Message content
        parts = line.strip().split("]: ", 1)
        header = parts[0].lstrip("[").split("] ")[0]
        message = parts[1] if len(parts) > 1 else ""
        event_type = "log"
        if ": " in message:
            split_msg = message.split(": ", 1)
            event_type = split_msg[0].strip().lower()
            content = split_msg[1].strip()
        else:
            content = message
        return {
            "timestamp": header,
            "type": event_type,
            "message": content
        }
    except Exception as e:
        print(f"[!] Failed to parse log line: {e}")
        return None

async def replay_events(ws_uri, delay=0.5, limit=None):
    print(f"[+] Starting playback to {ws_uri} (delay={delay}s)...")

    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}")
        return

    async with websockets.connect(ws_uri) as ws:
        with open(LOG_FILE, "r") as f:
            count = 0
            for line in f:
                if limit and count >= limit:
                    break
                event = parse_log_line(line)
                if event:
                    await ws.send(json.dumps(event))
                    print(f"[→] Sent: {event['type']} - {event['message']}")
                    await asyncio.sleep(delay)
                    count += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay historical logs to WebSocket dashboard")
    parser.add_argument("--target", default="ws://localhost:8765", help="WebSocket target URI")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between messages (seconds)")
    parser.add_argument("--limit", type=int, help="Optional limit on number of messages sent")
    args = parser.parse_args()

    try:
        asyncio.run(replay_events(args.target, args.delay, args.limit))
    except KeyboardInterrupt:
        print("[!] Playback interrupted.")
