# webgui/playback_panel.py
import time
import json
import os
import argparse
import websockets
import asyncio

LOG_FILE = "logs/dashboard/dashboard_stream.log"

async def replay_events(ws_uri, speed=1.0):
    print(f"[+] Replaying events to {ws_uri}...")
    with open(LOG_FILE, "r") as f:
        for line in f:
            await asyncio.sleep(speed)
            try:
                msg = line.split("]: ", 1)[1].strip()
                data = {"type": "log", "message": msg}
                async with websockets.connect(ws_uri) as ws:
                    await ws.send(json.dumps(data))
            except Exception as e:
                print(f"[!] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--speed", type=float, default=1.0, help="Delay between messages")
    parser.add_argument("--target", default="ws://localhost:8765", help="WebSocket target")
    args = parser.parse_args()

    asyncio.run(replay_events(args.target, args.speed))
