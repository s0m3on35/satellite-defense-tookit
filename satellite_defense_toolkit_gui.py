import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import threading
import os
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime

MODULES = {
    "GNSS AI Anomaly Detector": "modules/gnss_ai_anomaly_detector.py",
    "RF Jammer Locator": "modules/rf_jammer_locator.py",
    "Firmware Watcher Agent": "modules/firmware_watcher_agent.py",
    "Telemetry LSTM Monitor": "modules/telemetry_lstm_monitor.py",
    "Copilot AI CLI Assistant": "copilot/copilot_ai.py",
    "Firmware STIX Export": "modules/firmware_stix_export.py",
    "Firmware PCAP Capture": "modules/firmware_pcap_export.py"
}

AGENT_LOG_PATH = "recon/agent_inventory.json"
os.makedirs("recon", exist_ok=True)
os.makedirs("logs", exist_ok=True)

USERNAME = "admin"
PASSWORD = "toolkit"

def login_screen():
    def validate_login():
        if user_entry.get() == USERNAME and pass_entry.get() == PASSWORD:
            login.destroy()
            build_gui()
        else:
            messagebox.showerror("Access Denied", "Invalid credentials")

    login = tk.Tk()
    login.title("Satellite Toolkit - Secure Login")
    login.geometry("300x150")

    tk.Label(login, text="Username").pack(pady=5)
    user_entry = tk.Entry(login)
    user_entry.pack()

    tk.Label(login, text="Password").pack(pady=5)
    pass_entry = tk.Entry(login, show="*")
    pass_entry.pack()

    tk.Button(login, text="Login", command=validate_login).pack(pady=10)
    login.mainloop()

def run_script(script_path):
    if not os.path.exists(script_path):
        append_log(f"[!] Module not found: {script_path}")
        return
    append_log(f"[✓] Launching {script_path}")
    threading.Thread(target=execute_script, args=(script_path,)).start()

def execute_script(path):
    try:
        process = subprocess.Popen(["python3", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            append_log(line)
    except Exception as e:
        append_log(f"[!] Execution error: {e}")

def append_log(text):
    log_box.insert(tk.END, f"{text}")
    log_box.see(tk.END)

def refresh_agent_data():
    if not os.path.exists(AGENT_LOG_PATH):
        append_log("[*] No agent data found.\n")
        return
    try:
        with open(AGENT_LOG_PATH, "r") as f:
            data = json.load(f)
        agent_box.delete(1.0, tk.END)
        for agent, info in data.items():
            agent_box.insert(tk.END, f"Agent: {agent}\n")
            for key, val in info.items():
                if isinstance(val, list):
                    agent_box.insert(tk.END, f"  {key}: {len(val)} entries\n")
                else:
                    agent_box.insert(tk.END, f"  {key}: {val}\n")
            agent_box.insert(tk.END, "-"*50 + "\n")
    except Exception as e:
        append_log(f"[!] Agent parse error: {e}")

def conditional_chain():
    try:
        with open("results/telemetry_anomalies.json", "r") as f:
            anomalies = json.load(f)
        if anomalies:
            append_log("[*] Anomalies detected. Chaining STIX export...")
            run_script("modules/firmware_stix_export.py")
        else:
            append_log("[*] No anomalies found.")
    except Exception:
        append_log("[!] Could not parse telemetry results.")

def show_telemetry_plot():
    try:
        data = json.load(open("results/telemetry_anomalies.json"))
        points = [a["point_id"] for a in data]
        values = [a["value"] for a in data]

        fig, ax = plt.subplots(figsize=(5, 3))
        ax.plot(values)
        ax.plot(points, [values[i] for i in points], 'ro')
        ax.set_title("Telemetry Anomaly Plot")

        canvas = FigureCanvasTkAgg(fig, master=telemetry_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()
    except:
        append_log("[!] Failed to plot telemetry anomalies")

def open_svg_viewer():
    if not os.path.exists("mitre_matrix.svg"):
        append_log("[!] mitre_matrix.svg not found.")
        return
    try:
        os.system("xdg-open mitre_matrix.svg" if os.name != "nt" else "start mitre_matrix.svg")
    except:
        append_log("[!] SVG viewer failed")

def build_gui():
    global root, log_box, agent_box, telemetry_frame

    root = tk.Tk()
    root.title("Satellite Defense Toolkit GUI")
    root.geometry("1100x700")

    tk.Label(root, text="Modules").grid(row=0, column=0, sticky="w", padx=5, pady=2)
    for idx, (name, path) in enumerate(MODULES.items()):
        btn = tk.Button(root, text=name, width=40, command=lambda p=path: run_script(p))
        btn.grid(row=idx+1, column=0, padx=5, pady=2, sticky="w")

    tk.Button(root, text="Refresh Agent Inventory", command=refresh_agent_data).grid(row=0, column=1, sticky="w", padx=5)
    tk.Button(root, text="Auto Chain from LSTM", command=conditional_chain).grid(row=1, column=1, sticky="w", padx=5)
    tk.Button(root, text="Open MITRE Matrix (SVG)", command=open_svg_viewer).grid(row=2, column=1, sticky="w", padx=5)
    tk.Button(root, text="Show Telemetry Plot", command=show_telemetry_plot).grid(row=3, column=1, sticky="w", padx=5)

    tk.Label(root, text="Live Logs").grid(row=15, column=0, sticky="w", padx=5)
    log_box = scrolledtext.ScrolledText(root, width=100, height=15)
    log_box.grid(row=16, column=0, columnspan=3, padx=5, pady=5)

    tk.Label(root, text="Agent Inventory Summary").grid(row=15, column=1, sticky="w", padx=5)
    agent_box = scrolledtext.ScrolledText(root, width=45, height=15)
    agent_box.grid(row=16, column=1, columnspan=2, padx=5, pady=5)

    telemetry_frame = tk.Frame(root)
    telemetry_frame.grid(row=17, column=0, columnspan=3, padx=5, pady=10)

    root.mainloop()

if __name__ == "__main__":
    login_screen()
