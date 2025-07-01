
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import threading
import os
import json
import time
import websocket

MODULES = {
    "GNSS Spoof Detector": "modules/gnss/gnss_ai_anomaly_detector.py",
    "RF Jammer Locator": "modules/rf/rf_jammer_locator.py",
    "Firmware Watcher": "modules/firmware/firmware_watcher_agent.py",
    "Telemetry Anomaly Detector": "modules/telemetry/telemetry_lstm_monitor.py",
    "YARA STIX Exporter": "modules/stix/yara_stix_exporter.py",
    "Firmware STIX Export": "modules/stix/firmware_stix_export.py",
    "Firewall Rule Generator": "modules/defense/firewall_rule_generator.py",
    "Firmware CVE Mapper": "modules/intel/firmware_cve_mapper.py",
    "Attack Frequency Heatmap": "modules/stats/attack_frequency_heatmap.py",
    "Firmware Timeline Builder": "modules/forensics/firmware_timeline_builder.py",
    "Agent Commander": "modules/c2/agent_commander.py"
}

DASHBOARD_WS_URL = "ws://localhost:8765"

class SatelliteDefenseGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Satellite Defense Toolkit Launcher")
        self.root.geometry("850x600")

        self.listbox = tk.Listbox(root, font=("Courier", 12), width=60, height=15)
        for module in MODULES:
            self.listbox.insert(tk.END, module)
        self.listbox.pack(pady=10)

        self.output = tk.Text(root, wrap="word", height=20, bg="black", fg="lime", font=("Courier", 10))
        self.output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        button_frame = tk.Frame(root)
        button_frame.pack()

        tk.Button(button_frame, text="Run Selected Module", command=self.run_selected_module).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Save Log", command=self.save_log).grid(row=0, column=1, padx=10)
        tk.Button(button_frame, text="Clear Log", command=self.clear_log).grid(row=0, column=2, padx=10)

        self.ws = None
        self.connect_to_websocket()

    def connect_to_websocket(self):
        try:
            self.ws = websocket.create_connection(DASHBOARD_WS_URL)
            self.send_dashboard_event("gui_online", "SatelliteDefenseGUI is now connected.")
        except Exception as e:
            self.ws = None
            self.log_output(f"[WebSocket] Dashboard connection failed: {e}")

    def send_dashboard_event(self, event_type, message):
        if self.ws:
            try:
                payload = {
                    "timestamp": time.time(),
                    "type": event_type,
                    "message": message
                }
                self.ws.send(json.dumps(payload))
            except:
                pass

    def run_selected_module(self):
        selected = self.listbox.get(tk.ACTIVE)
        script = MODULES.get(selected)
        if not script or not os.path.exists(script):
            self.log_output(f"[!] Module script not found: {script}")
            return

        self.send_dashboard_event("module_run", f"{selected} launched.")
        self.log_output(f"[+] Running: {selected}")
        threading.Thread(target=self.run_script, args=(script, selected), daemon=True).start()

    def run_script(self, script, name):
        try:
            proc = subprocess.Popen(["python3", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                self.log_output(line.strip())
                self.send_dashboard_event("log", f"{name}: {line.strip()}")
        except Exception as e:
            self.log_output(f"[!] Error running module: {e}")

    def log_output(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log Files", "*.log")])
        if path:
            with open(path, "w") as f:
                f.write(self.output.get("1.0", tk.END))
            self.log_output(f"[✓] Log saved: {path}")

    def clear_log(self):
        self.output.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SatelliteDefenseGUI(root)
    root.mainloop()
