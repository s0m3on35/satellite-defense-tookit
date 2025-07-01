import tkinter as tk
from tkinter import filedialog, scrolledtext
import subprocess
import threading
import os
import datetime

LOG_DIR = "logs"
RESULTS_DIR = "results"
DEFAULT_IFACE = "eth0"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

def run_cmd(cmd):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            output_text.insert(tk.END, line)
            output_text.see(tk.END)
    except Exception as e:
        output_text.insert(tk.END, f"[ERROR] {e}\n")
        output_text.see(tk.END)

def run_pcap_capture():
    iface = iface_entry.get().strip()
    timeout = int(timeout_entry.get().strip())
    enable_stix = stix_var.get()
    enable_yara = yara_var.get()
    enable_plot = plot_var.get()
    log_file = f"{LOG_DIR}/gui_capture_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.log"

    cmd = [
        "python3", "firmware_pcap_export.py",
        "--iface", iface,
        "--timeout", str(timeout),
        "--log", log_file
    ]
    if enable_stix:
        cmd.append("--stix")
    if enable_yara:
        cmd.append("--yara")
    if enable_plot:
        cmd.append("--plot")

    output_text.insert(tk.END, f"[+] Executing: {' '.join(cmd)}\n")
    threading.Thread(target=run_cmd, args=(cmd,), daemon=True).start()

def run_stix_export():
    fw_path = filedialog.askopenfilename(title="Select Firmware Binary")
    if not fw_path:
        return
    enable_dashboard = dash_var.get()
    enable_ws = ws_var.get()
    log_file = f"{LOG_DIR}/gui_stix_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.log"

    cmd = [
        "python3", "firmware_stix_export.py",
        "--firmware", fw_path,
        "--log", log_file
    ]
    if enable_dashboard:
        cmd.append("--dashboard")
    if enable_ws:
        cmd.append("--ws")

    output_text.insert(tk.END, f"[+] Analyzing firmware: {fw_path}\n")
    threading.Thread(target=run_cmd, args=(cmd,), daemon=True).start()

root = tk.Tk()
root.title("Satellite Defense Toolkit GUI")
root.geometry("850x650")

tk.Label(root, text="Network Interface:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
iface_entry = tk.Entry(root, width=20)
iface_entry.insert(0, DEFAULT_IFACE)
iface_entry.grid(row=0, column=1, padx=5, pady=2)

tk.Label(root, text="Capture Timeout (seconds):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
timeout_entry = tk.Entry(root, width=10)
timeout_entry.insert(0, "30")
timeout_entry.grid(row=1, column=1, padx=5, pady=2)

stix_var = tk.BooleanVar()
tk.Checkbutton(root, text="Auto STIX Export After PCAP", variable=stix_var).grid(row=2, column=0, columnspan=2, sticky="w", padx=5)

yara_var = tk.BooleanVar()
tk.Checkbutton(root, text="Enable YARA Signature Matching", variable=yara_var).grid(row=3, column=0, columnspan=2, sticky="w", padx=5)

plot_var = tk.BooleanVar()
tk.Checkbutton(root, text="Live PCAP Graph Plotting", variable=plot_var).grid(row=4, column=0, columnspan=2, sticky="w", padx=5)

dash_var = tk.BooleanVar()
tk.Checkbutton(root, text="Send STIX Alert to Dashboard", variable=dash_var).grid(row=5, column=0, columnspan=2, sticky="w", padx=5)

ws_var = tk.BooleanVar()
tk.Checkbutton(root, text="Enable WebSocket Dashboard Stream", variable=ws_var).grid(row=6, column=0, columnspan=2, sticky="w", padx=5)

tk.Button(root, text="Capture PCAP", command=run_pcap_capture, bg="#4CAF50", fg="white", width=25).grid(row=7, column=0, padx=5, pady=10)
tk.Button(root, text="Analyze Firmware (STIX)", command=run_stix_export, bg="#2196F3", fg="white", width=30).grid(row=7, column=1, padx=5, pady=10)

output_text = scrolledtext.ScrolledText(root, width=100, height=25)
output_text.grid(row=8, column=0, columnspan=3, padx=5, pady=10)

tk.Label(root, text="Satellite Defense Toolkit - GUI Interface", fg="gray").grid(row=9, column=0, sticky="w", padx=5)

root.mainloop()
