#!/usr/bin/env python3
# Ruta: modules/gui/firmware_gui_trigger.py


import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import threading
import os
import json
import logging

LOG_FILE = "logs/gui/firmware_gui_trigger.log"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='[%(asctime)s] %(message)s')

class FirmwareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Satellite Toolkit – Firmware & PCAP Analysis")
        self.file_path = tk.StringVar()
        self.module_choice = tk.StringVar(value="stix_export")
        self.dashboard = tk.BooleanVar(value=True)
        self.taxii = tk.BooleanVar(value=False)
        self.setup_gui()

    def setup_gui(self):
        frm = tk.Frame(self.root, padx=10, pady=10)
        frm.pack()

        tk.Label(frm, text="Select Firmware/PCAP File:", anchor="w").grid(row=0, column=0, sticky="w")
        tk.Entry(frm, textvariable=self.file_path, width=60).grid(row=1, column=0)
        tk.Button(frm, text="Browse", command=self.browse_file).grid(row=1, column=1, padx=5)

        tk.Label(frm, text="Select Module:").grid(row=2, column=0, sticky="w", pady=(10, 0))
        ttk.Combobox(frm, textvariable=self.module_choice,
                     values=["stix_export", "pcap_export", "both"]).grid(row=3, column=0, sticky="w")

        tk.Checkbutton(frm, text="Send to Dashboard", variable=self.dashboard).grid(row=4, column=0, sticky="w")
        tk.Checkbutton(frm, text="Send to TAXII Server", variable=self.taxii).grid(row=5, column=0, sticky="w")

        tk.Button(frm, text="Run Analysis", command=self.run_analysis, bg="#222", fg="white").grid(row=6, column=0, pady=12)

        self.output_box = tk.Text(self.root, height=20, width=100, bg="#111", fg="#0f0", insertbackground="#0f0")
        self.output_box.pack(padx=10, pady=5)

    def browse_file(self):
        filetypes = [
            ("Firmware or PCAP", "*.bin *.img *.pcapng *.pcap"),
            ("All Files", "*.*")
        ]
        filename = filedialog.askopenfilename(title="Select input file", filetypes=filetypes)
        if filename:
            self.file_path.set(filename)

    def run_analysis(self):
        if not os.path.isfile(self.file_path.get()):
            messagebox.showerror("Invalid file", "Please select a valid firmware or PCAP file.")
            return

        self.output_box.delete(1.0, tk.END)
        thread = threading.Thread(target=self.execute_modules)
        thread.start()

    def execute_modules(self):
        input_file = self.file_path.get()
        module = self.module_choice.get()

        if module in ["stix_export", "both"]:
            stix_cmd = [
                "python3", "modules/firmware_stix_export.py",
                "--firmware", input_file,
                "--collection", "default",
                "--user", "user",
                "--password", "pass"
            ]
            if self.dashboard.get(): stix_cmd.append("--dashboard")
            if self.taxii.get(): stix_cmd.append("--taxii")
            self.run_command(stix_cmd)

        if module in ["pcap_export", "both"]:
            pcap_cmd = [
                "python3", "modules/firmware_pcap_export.py",
                "--pcap", input_file
            ]
            if self.dashboard.get(): pcap_cmd.append("--chain-stix")
            self.run_command(pcap_cmd)

    def run_command(self, cmd):
        self.output_box.insert(tk.END, f"\n[RUNNING] {' '.join(cmd)}\n")
        logging.info(f"Executing: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()

            if stdout:
                decoded_out = stdout.decode(errors="ignore")
                self.output_box.insert(tk.END, decoded_out)
                logging.info(decoded_out)

            if stderr:
                decoded_err = stderr.decode(errors="ignore")
                self.output_box.insert(tk.END, f"\n[ERROR]\n{decoded_err}")
                logging.error(decoded_err)

            self.output_box.insert(tk.END, f"\n[EXIT CODE]: {proc.returncode}\n")
            logging.info(f"Exit code: {proc.returncode}")

        except Exception as e:
            error_msg = f"Exception occurred: {str(e)}"
            self.output_box.insert(tk.END, f"\n[EXCEPTION] {error_msg}\n")
            logging.error(error_msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = FirmwareGUI(root)
    root.mainloop()
