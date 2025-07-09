#!/usr/bin/env python3
# Route: satellite_defense_toolkit_gui.py (God-mode Enhanced)

import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
import subprocess
import threading
import os
import json
import time
import websocket

DASHBOARD_WS_URL = "ws://localhost:8765"
AUDIT_TRAIL_LOG = "logs/audit_trail.jsonl"

MODULE_GROUPS = {
    "Defense": {
        "Binary Integrity Watcher": "modules/defense/binary_integrity_watcher.py",
        "Firewall Rule Generator": "modules/defense/firewall_rule_generator.py",
        "Firmware Integrity Watcher": "modules/defense/firmware_integrity_watcher.py",
        "Firmware Memory Shield": "modules/defense/firmware_memory_shield.py",
        "Firmware Rollback Protector": "modules/defense/firmware_rollback_protector.py",
        "Firmware Signature Validator": "modules/defense/firmware_signature_validator.py",
        "GNSS Spoof Guard": "modules/defense/gnss_spoof_guard.py",
        "Interface Integrity Monitor": "modules/defense/interface_integrity_monitor.py",
        "Kernel Module Guard": "modules/defense/kernel_module_guard.py",
        "Live Integrity Watcher": "modules/defense/live_integrity_watcher.py",
        "OTA Guard": "modules/defense/ota_guard.py",
        "OTA Stream Guard": "modules/defense/ota_stream_guard.py",
        "RF Injection Barrier": "modules/defense/rf_injection_barrier.py",
        "Secure Update Guard": "modules/defense/secure_update_guard.py",
        "System Call Anomaly Watcher": "modules/defense/system_call_anomaly_watcher.py",
        "Telemetry Guardian": "modules/defense/telemetry_guardian.py"
    },
    "AI & Analysis": {
        "Threat Classifier AI": "modules/ai/threat_classifier.py",
        "Threat Summary LLM": "modules/ai/threat_summary_llm.py",
        "AI Copilot Engine": "modules/copilot/copilot_ai.py"
    },
    "Forensics": {
        "Firmware Timeline Builder": "modules/forensics/firmware_timeline_builder.py",
        "Memwatch Agent": "modules/forensics/memwatch_agent.py",
        "OTA Packet Analyzer": "modules/forensics/ota_packet_analyzer.py"
    }
}

class SatelliteDefenseToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Satellite Defense Toolkit — God Mode")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0f0f0f")
        self.ws = None
        self.run_history = []

        self.connect_to_websocket()
        self.create_interface()

    def connect_to_websocket(self):
        try:
            self.ws = websocket.create_connection(DASHBOARD_WS_URL, timeout=3)
            self.send_dashboard_event("gui_online", "GUI launched in God mode")
        except Exception as e:
            self.log(f"[WebSocket] Offline: {e}")

    def send_dashboard_event(self, evt_type, msg):
        if self.ws:
            try:
                self.ws.send(json.dumps({"timestamp": time.time(), "type": evt_type, "message": msg}))
            except:
                self.ws = None

    def create_interface(self):
        self.tab_control = ttk.Notebook(self.root)
        self.module_listboxes = {}

        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.search_modules)
        search_entry = tk.Entry(self.root, textvariable=self.search_var, font=("Courier", 12), width=40)
        search_entry.pack(pady=5)

        for category, modules in MODULE_GROUPS.items():
            tab = ttk.Frame(self.tab_control)
            self.tab_control.add(tab, text=category)
            listbox = tk.Listbox(tab, font=("Courier", 11), width=90, height=25, bg="black", fg="lime", selectbackground="#444")
            for module in modules:
                listbox.insert(tk.END, module)
            listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            self.module_listboxes[category] = listbox

        self.tab_control.pack(expand=True, fill="both")

        self.output = tk.Text(self.root, height=10, bg="black", fg="lime", font=("Courier", 10))
        self.output.pack(fill=tk.BOTH, padx=10, pady=5, expand=False)

        buttons = tk.Frame(self.root, bg="#0f0f0f")
        buttons.pack(pady=5)

        tk.Button(buttons, text="Run Module", command=self.run_selected_module, width=20).pack(side=tk.LEFT, padx=10)
        tk.Button(buttons, text="Clear Log", command=self.clear_log, width=20).pack(side=tk.LEFT, padx=10)
        tk.Button(buttons, text="Save Log", command=self.save_log, width=20).pack(side=tk.LEFT, padx=10)
        tk.Button(buttons, text="Run Sequence", command=self.run_module_chain, width=20).pack(side=tk.LEFT, padx=10)

    def get_active_module(self):
        current_tab = self.tab_control.tab(self.tab_control.select(), "text")
        listbox = self.module_listboxes.get(current_tab)
        selected = listbox.get(tk.ACTIVE)
        path = MODULE_GROUPS[current_tab][selected]
        return selected, path

    def run_selected_module(self):
        name, path = self.get_active_module()
        if not os.path.exists(path):
            self.log(f"[Error] Script not found: {path}")
            return
        args = simpledialog.askstring("Arguments", f"Enter arguments for {name} (or leave blank):")
        self.log(f"[+] Running {name} {'with args: ' + args if args else ''}")
        self.send_dashboard_event("module_run", f"{name} launched")
        self.run_history.append(name)
        self.log_audit(name, path, args)
        threading.Thread(target=self.run_script, args=(path, name, args), daemon=True).start()

    def run_module_chain(self):
        chain = simpledialog.askstring("Module Chain", "Enter modules separated by commas:")
        if not chain:
            return
        for mod in chain.split(","):
            mod = mod.strip()
            for category, group in MODULE_GROUPS.items():
                if mod in group:
                    path = group[mod]
                    args = ""
                    self.log(f"[CHAIN] Running {mod}")
                    self.send_dashboard_event("module_chain", f"{mod} in chain")
                    self.log_audit(mod, path, args)
                    threading.Thread(target=self.run_script, args=(path, mod, args), daemon=True).start()
                    time.sleep(2)

    def run_script(self, script, name, args=""):
        try:
            cmd = ["python3", script] + args.split() if args else ["python3", script]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                self.log(f"[{name}] {line.strip()}")
        except Exception as e:
            self.log(f"[Exception] {name} failed: {e}")

    def log_audit(self, name, path, args=""):
        os.makedirs("logs", exist_ok=True)
        audit = {
            "timestamp": time.time(),
            "module": name,
            "path": path,
            "args": args,
            "event": "execution"
        }
        with open(AUDIT_TRAIL_LOG, "a") as f:
            f.write(json.dumps(audit) + "\n")

    def log(self, msg):
        self.output.insert(tk.END, msg + "\n")
        self.output.see(tk.END)

    def clear_log(self):
        self.output.delete("1.0", tk.END)

    def save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log files", "*.log")])
        if path:
            with open(path, "w") as f:
                f.write(self.output.get("1.0", tk.END))
            self.log(f"[✓] Saved to {path}")

    def search_modules(self, *args):
        query = self.search_var.get().lower()
        for cat, listbox in self.module_listboxes.items():
            listbox.delete(0, tk.END)
            for module in MODULE_GROUPS[cat]:
                if query in module.lower():
                    listbox.insert(tk.END, module)

if __name__ == "__main__":
    root = tk.Tk()
    app = SatelliteDefenseToolkitGUI(root)
    root.mainloop()
