#!/usr/bin/env python3
# Route: satellite_defense_toolkit_cli.py

import os
import json
import time
import subprocess
import argparse
from pathlib import Path
import websocket
import sys

DASHBOARD_WS_URL = "ws://localhost:8765"
AUDIT_LOG = Path("logs/cli_audit_log.jsonl")
EXEC_LOG = Path("results/cli_execution_log.txt")
AGENTS_FILE = Path("config/agent_inventory.json")

MODULES = {
    "Defense": "modules/defense",
    "AI & Analysis": "modules/ai",
    "Forensics": "modules/forensics",
    "Attacks": "modules/attacks",
    "C2": "modules/c2"
}

def prepare_environment():
    """Ensure required directories and files exist."""
    for path in [AUDIT_LOG.parent, EXEC_LOG.parent, AGENTS_FILE.parent]:
        path.mkdir(parents=True, exist_ok=True)
    if not AGENTS_FILE.exists():
        AGENTS_FILE.write_text("[]")

def list_modules():
    """List all available modules across categories."""
    mod_list = []
    for category, path in MODULES.items():
        if os.path.exists(path):
            for f in os.listdir(path):
                if f.endswith(".py"):
                    mod_list.append((category, f.replace(".py", ""), os.path.join(path, f)))
    return mod_list

def choose_agent():
    """Present agents to the user and return selected one."""
    try:
        agents = json.loads(AGENTS_FILE.read_text())
    except Exception as e:
        print(f"[!] Error reading agents: {e}")
        return None

    if not agents:
        return None

    print("\n[Agent Selector]")
    for idx, agent in enumerate(agents, 1):
        print(f"  [{idx}] {agent.get('name', 'Unnamed')} ({agent.get('ip', '-')})")

    choice = input("Select agent [number or blank]: ").strip()
    if choice.isdigit() and 0 < int(choice) <= len(agents):
        return agents[int(choice)-1]
    return None

def send_ws_event(event_type, message):
    """Send event to WebSocket dashboard (non-blocking)."""
    try:
        ws = websocket.create_connection(DASHBOARD_WS_URL, timeout=3)
        ws.send(json.dumps({
            "timestamp": time.time(),
            "type": event_type,
            "message": message
        }))
        ws.close()
    except:
        pass  # Dashboard offline or unreachable

def log_execution(module_name, path, args, agent):
    entry = {
        "timestamp": time.time(),
        "module": module_name,
        "path": path,
        "args": args,
        "agent": agent,
        "event": "execution"
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def run_module(path, args, module_name):
    cmd = ["python3", path] + args.split()
    print(f"\n[+] Running module: {module_name}")
    print(f"[>] Command: {' '.join(cmd)}")
    with open(EXEC_LOG, "a") as logf:
        logf.write(f"\n===== {module_name} @ {time.ctime()} =====\n")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                print(f"[{module_name}] {line.strip()}")
                logf.write(line)
        except Exception as e:
            print(f"[!] Error: {e}")
            logf.write(f"[!] Exception: {e}\n")

def chain_mode(mods):
    print("\n[Chain Mode] Enter module numbers separated by commas (e.g., 1,2,5):")
    for idx, (cat, mod, _) in enumerate(mods, 1):
        print(f"[{idx:02}] {cat:20} - {mod}")
    sel = input("\nModules to chain: ").strip()
    delay = input("Delay between modules (seconds, default 2): ").strip()
    delay = int(delay) if delay.isdigit() else 2

    agent = choose_agent()
    parts = [p.strip() for p in sel.split(",") if p.strip().isdigit()]

    for part in parts:
        idx = int(part) - 1
        if 0 <= idx < len(mods):
            _, name, path = mods[idx]
            args = input(f"Args for {name} (blank = none): ").strip()
            log_execution(name, path, args, agent)
            send_ws_event("module_chain", f"{name} chained via CLI")
            run_module(path, args, name)
            time.sleep(delay)

def interactive_menu():
    """Main CLI interface loop."""
    while True:
        print("\nSatellite Defense Toolkit CLI")
        print("="*40)
        mods = list_modules()
        if not mods:
            print("[!] No modules found. Ensure paths are correct.")
            break

        for idx, (cat, mod, _) in enumerate(mods, 1):
            print(f"[{idx:02}] {cat:20} - {mod}")
        print("[C] Chain multiple modules")
        print("[Q] Quit")

        choice = input("\nSelect option: ").strip().lower()
        if choice == 'q':
            print("[✓] Exiting.")
            break
        elif choice == 'c':
            chain_mode(mods)
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(mods):
                _, name, path = mods[idx]
                args = input(f"Args for {name} (leave blank for none): ").strip()
                agent = choose_agent()
                log_execution(name, path, args, agent)
                send_ws_event("module_run", f"{name} run via CLI")
                run_module(path, args, name)
        else:
            print("[!] Invalid input. Try again.")

def main():
    prepare_environment()
    interactive_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[✓] Interrupted by user. Exiting.")
        sys.exit(0)
