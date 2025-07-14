##!/usr/bin/env python3
# Route: satellite_defense_toolkit_cli.py

import os
import json
import time
import subprocess
import argparse
import readline
from pathlib import Path
import websocket

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

# Ensure paths exist
def prepare_environment():
    for path in [AUDIT_LOG.parent, EXEC_LOG.parent, AGENTS_FILE.parent]:
        path.mkdir(parents=True, exist_ok=True)
    if not AGENTS_FILE.exists():
        AGENTS_FILE.write_text("[]")

def list_modules():
    mod_list = []
    for category, path in MODULES.items():
        if os.path.exists(path):
            for f in os.listdir(path):
                if f.endswith(".py"):
                    mod_list.append((category, f.replace(".py", ""), os.path.join(path, f)))
    return mod_list

def choose_agent():
    agents = json.loads(AGENTS_FILE.read_text())
    if not agents:
        return None
    print("\nAvailable Agents:")
    for idx, agent in enumerate(agents, 1):
        print(f"  [{idx}] {agent.get('name', 'Unnamed')} ({agent.get('ip', '-')})")
    choice = input("Select agent [number or blank for none]: ")
    if choice.isdigit() and 0 < int(choice) <= len(agents):
        return agents[int(choice)-1]
    return None

def send_ws_event(event_type, message):
    try:
        ws = websocket.create_connection(DASHBOARD_WS_URL, timeout=3)
        ws.send(json.dumps({
            "timestamp": time.time(),
            "type": event_type,
            "message": message
        }))
        ws.close()
    except Exception:
        pass  # Silent fail if dashboard is offline

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
    print(f"\n[+] Running: {module_name}")
    print(f"Command: {' '.join(cmd)}\n")
    with open(EXEC_LOG, "a") as logf:
        logf.write(f"\n===== {module_name} @ {time.ctime()} =====\n")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                print(line.strip())
                logf.write(line)
        except Exception as e:
            print(f"[!] Failed: {e}")
            logf.write(f"[!] Exception: {e}\n")

def interactive_menu():
    print("\nSatellite Defense Toolkit CLI")
    print("="*40)
    mods = list_modules()
    for idx, (cat, mod, _) in enumerate(mods, 1):
        print(f"[{idx}] {cat:16} - {mod}")
    print("[C] Chain modules")
    print("[Q] Quit")
    choice = input("\nSelect option: ").strip()
    if choice.lower() == 'q':
        return
    elif choice.lower() == 'c':
        chain_mode(mods)
        return
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(mods):
            _, name, path = mods[idx]
            args = input(f"Args for {name} (leave blank for none): ").strip()
            agent = choose_agent()
            log_execution(name, path, args, agent)
            send_ws_event("module_run", f"{name} run via CLI")
            run_module(path, args, name)

def chain_mode(mods):
    print("\nChain Mode — use numbers separated by commas (e.g. 1,3,5)")
    for idx, (cat, mod, _) in enumerate(mods, 1):
        print(f"[{idx}] {cat:16} - {mod}")
    sel = input("\nModules to chain: ").strip()
    if not sel:
        return
    parts = sel.split(",")
    agent = choose_agent()
    for part in parts:
        if part.strip().isdigit():
            idx = int(part.strip()) - 1
            if 0 <= idx < len(mods):
                _, name, path = mods[idx]
                args = input(f"Args for {name} (blank = none): ").strip()
                log_execution(name, path, args, agent)
                send_ws_event("module_chain", f"{name} chained via CLI")
                run_module(path, args, name)

def main():
    prepare_environment()
    while True:
        interactive_menu()

if __name__ == "__main__":
    main()
