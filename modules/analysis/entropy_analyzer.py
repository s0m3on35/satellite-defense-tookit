import tkinter as tk
from tkinter import scrolledtext, filedialog
import subprocess
import threading
import os
import json
import datetime
import websocket
import ssl

LOG_PATH = "logs"
RESULTS_PATH = "results"
STIX_MODULE = "modules/firmware_stix_export.py"
ENTROPY_SCRIPT = "modules/entropy_analyzer.py"
COPILOT_TRIGGER = "copilot/copilot_ai.py"
WS_ENDPOINT = "ws://localhost:9999/entropy"

os.makedirs(LOG_PATH, exist_ok=True)
os.makedirs(RESULTS_PATH, exist_ok=True)

def append_log(msg):
    log_box.insert(tk.END, msg + "\n")
    log_box.see(tk.END)

def run_script(cmd):
    def _run():
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                append_log(line.strip())
        except Exception as e:
            append_log(f"[ERROR] {e}")
    threading.Thread(target=_run, daemon=True).start()

def run_entropy_scan():
    target = filedialog.askopenfilename(title="Select File or Firmware")
    if not target:
        return
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    log_file = f"{LOG_PATH}/entropy_gui_{timestamp}.log"
    cmd = ["python3", ENTROPY_SCRIPT, "--input", target, "--log", log_file, "--json"]
    append_log(f"[+] Running: {' '.join(cmd)}")
    run_script(cmd)

def check_entropy_results_and_stix():
    try:
        with open(f"{RESULTS_PATH}/entropy_anomalies.json") as f:
            data = json.load(f)
        if data.get("anomalies_detected"):
            append_log("[*] Anomalies found. Triggering STIX export...")
            run_script(["python3", STIX_MODULE, "--from-entropy"])
        else:
            append_log("[*] No critical anomalies.")
    except Exception as e:
        append_log(f"[ERROR] Could not load anomalies: {e}")

def launch_copilot_suggestion():
    run_script(["python3", COPILOT_TRIGGER, "--context", "entropy"])

def ws_listener():
    def on_message(ws, msg):
        append_log(f"[WS] {msg}")

    def on_error(ws, err):
        append_log(f"[WS ERROR] {err}")

    def on_close(ws, code, msg):
        append_log("[WS] Connection closed.")

    def _ws():
        ws = websocket.WebSocketApp(WS_ENDPOINT, on_message=on_message, on_error=on_error, on_close=on_close)
        ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
    threading.Thread(target=_ws, daemon=True).start()

root = tk.Tk()
root.title("Entropy Analyzer - Satellite Defense Toolkit")
root.geometry("900x600")

tk.Button(root, text="Start Entropy Scan", width=30, command=run_entropy_scan, bg="#4CAF50", fg="white").grid(row=0, column=0, padx=5, pady=5)
tk.Button(root, text="Analyze and Export STIX", width=30, command=check_entropy_results_and_stix, bg="#2196F3", fg="white").grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="Trigger Copilot Advice", width=30, command=launch_copilot_suggestion, bg="#795548", fg="white").grid(row=1, column=0, padx=5, pady=5)
tk.Button(root, text="Start WebSocket Listener", width=30, command=ws_listener, bg="#9C27B0", fg="white").grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="Live Log Output").grid(row=2, column=0, columnspan=2)
log_box = scrolledtext.ScrolledText(root, width=110, height=30)
log_box.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

tk.Label(root, text="© Satellite Defense Toolkit - Entropy GUI").grid(row=4, column=0, sticky="w", padx=5)

root.mainloop()
