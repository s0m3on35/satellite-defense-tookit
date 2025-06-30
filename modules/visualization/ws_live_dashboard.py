import websocket
import threading
import json
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from datetime import datetime

# === Configuration ===
WS_URL = "ws://localhost:8765"
RECONNECT_INTERVAL = 5

console = Console()
alerts = []

# === Terminal Layout Setup ===
def create_layout():
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="alerts"),
        Layout(name="stats")
    )
    return layout

def render_header():
    return Panel(Text(" SATELLITE DEFENSE TOOLKIT — LIVE ALERT STREAM", style="bold white on blue"), border_style="bright_blue")

def render_footer():
    return Panel(Text(f"Listening on {WS_URL} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim"), border_style="grey37")

def render_alert_table():
    table = Table(title="Live Anomaly Alerts", expand=True, show_lines=True)
    table.add_column("Timestamp", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Source", style="green")
    table.add_column("Value", style="yellow")
    table.add_column("Details", style="white")

    for alert in alerts[-20:]:
        table.add_row(
            alert.get("timestamp", "—"),
            alert.get("alert", "—"),
            alert.get("source", "—"),
            str(alert.get("value", "—")),
            alert.get("description", "—")
        )
    return table

def render_stats():
    stats_panel = Table(title="Stats", expand=True)
    total = len(alerts)
    anomaly_types = {}
    for a in alerts:
        key = a.get("alert", "unknown")
        anomaly_types[key] = anomaly_types.get(key, 0) + 1
    stats_panel.add_column("Anomaly Type")
    stats_panel.add_column("Count")
    for k, v in anomaly_types.items():
        stats_panel.add_row(k, str(v))
    return stats_panel

# === WebSocket Client ===
def on_message(ws, message):
    try:
        data = json.loads(message)
        data.setdefault("timestamp", datetime.utcnow().isoformat())
        data.setdefault("source", "telemetry_stream")
        data.setdefault("alert", "unknown")
        data.setdefault("description", "No description provided")
        alerts.append(data)
    except Exception as e:
        console.log(f"[!] Failed to parse message: {e}")

def on_error(ws, error):
    console.log(f"[!] WebSocket error: {error}")

def on_close(ws, close_status_code, close_msg):
    console.log(f"[!] WebSocket connection closed: {close_status_code} {close_msg}")

def on_open(ws):
    console.log(f"[✓] Connected to WebSocket: {WS_URL}")

def start_ws_client():
    while True:
        try:
            ws = websocket.WebSocketApp(
                WS_URL,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close
            )
            ws.run_forever()
        except Exception as e:
            console.log(f"[!] WebSocket connection failed: {e}")
        console.log(f"[~] Reconnecting in {RECONNECT_INTERVAL}s...")
        time.sleep(RECONNECT_INTERVAL)

# === Main ===
def main():
    layout = create_layout()
    threading.Thread(target=start_ws_client, daemon=True).start()

    with Live(layout, refresh_per_second=2, screen=True):
        while True:
            layout["header"].update(render_header())
            layout["footer"].update(render_footer())
            layout["alerts"].update(render_alert_table())
            layout["stats"].update(render_stats())
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[!] Interrupted. Exiting...")
