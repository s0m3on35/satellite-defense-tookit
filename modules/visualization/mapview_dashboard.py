# modules/visualization/

import json
import os
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich import box
from datetime import datetime

AGENT_FILE = "recon/agent_inventory.json"
REFRESH_INTERVAL = 5
console = Console()

def load_agents():
    if not os.path.exists(AGENT_FILE):
        return {}
    with open(AGENT_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def render_header():
    return Panel(Text("SATELLITE DEFENSE TOOLKIT — MULTI-AGENT MAP VIEW", style="bold white on blue"), border_style="bright_blue")

def render_footer(agent_count):
    return Panel(Text(f"Live Agents: {agent_count} | {datetime.utcnow().isoformat()}", style="dim"), border_style="grey37")

def render_agent_map(agents):
    table = Table.grid(expand=True)
    map_grid = [["." for _ in range(40)] for _ in range(20)]

    for agent_id, agent in agents.items():
        lat = float(agent.get("lat", 0))
        lon = float(agent.get("lon", 0))
        x = int((lon + 180) / 360 * 40)
        y = int((90 - lat) / 180 * 20)
        x = max(0, min(x, 39))
        y = max(0, min(y, 19))
        map_grid[y][x] = "X"

    map_str = "\n".join("".join(row) for row in map_grid)
    return Panel(map_str, title="Global Agent Map (ASCII)", border_style="green")

def render_agent_table(agents):
    table = Table(title="Agent Inventory", box=box.SIMPLE, expand=True)
    table.add_column("Agent", style="cyan", no_wrap=True)
    table.add_column("IP", style="green")
    table.add_column("OS", style="magenta")
    table.add_column("Location", style="yellow")
    table.add_column("Alerts", style="red")

    for agent_id, agent in agents.items():
        lat = agent.get("lat", "N/A")
        lon = agent.get("lon", "N/A")
        ip = agent.get("ip", "—")
        osys = agent.get("os", "—")
        alerts = str(len(agent.get("telemetry", [])))
        table.add_row(agent_id, ip, osys, f"{lat},{lon}", alerts)

    return table

def create_layout():
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=2)
    )
    layout["main"].split_row(
        Layout(name="map", ratio=1),
        Layout(name="inventory", ratio=2)
    )
    return layout

def main():
    layout = create_layout()

    with Live(layout, refresh_per_second=1, screen=True):
        while True:
            agents = load_agents()
            layout["header"].update(render_header())
            layout["footer"].update(render_footer(len(agents)))
            layout["map"].update(render_agent_map(agents))
            layout["inventory"].update(render_agent_table(agents))
            time.sleep(REFRESH_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[!] Interrupted. Exiting...")
