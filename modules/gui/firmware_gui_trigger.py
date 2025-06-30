import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import threading
import os
import json

class FirmwareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firmware Analysis Launcher")

        self.file_path = tk.StringVar()
        self.module_choice = tk.StringVar(value="stix_export")

        self.dashboard = tk.BooleanVar(value=True)
        self.taxii = tk.BooleanVar(value=False)

        self.setup_gui()

    def setup_gui(self):
        tk.Label(self.root, text="Select Firmware/PCAP File:").pack(pady=5)
        tk.Entry(self.root, textvariable=self.file_path, width=50).pack()
        tk.Button(self.root, text="Browse", command=self.browse_file).pack(pady=5)

        tk.Label(self.root, text="Select Module:").pack(pady=5)
        ttk.Combobox(self.root, textvariable=self.module_choice,
                     values=["stix_export", "pcap_export", "both"]).pack()

        tk.Checkbutton(self.root, text="Send to Dashboard", variable=self.dashboard).pack()
        tk.Checkbutton(self.root, text="Send to TAXII Server", variable=self.taxii).pack()

        tk.Button(self.root, text="Run", command=self.run_analysis).pack(pady=10)
        self.output_box = tk.Text(self.root, height=15, width=80)
        self.output_box.pack()

    def browse_file(self):
        filetypes = [("Firmware or PCAP", "*.bin *.img *.pcapng *.pcap"), ("All Files", "*.*")]
        filename = filedialog.askopenfilename(title="Select file", filetypes=filetypes)
        self.file_path.set(filename)

    def run_analysis(self):
        if not self.file_path.get():
            messagebox.showwarning("Input needed", "Please select a firmware or PCAP file.")
            return

        self.output_box.delete(1.0, tk.END)
        thread = threading.Thread(target=self.execute_modules)
        thread.start()

    def execute_modules(self):
        cmd_base = f"python3"
        file_arg = self.file_path.get()

        if self.module_choice.get() in ["stix_export", "both"]:
            stix_cmd = [
                cmd_base, "modules/firmware_stix_export.py",
                "--firmware", file_arg,
                "--dashboard" if self.dashboard.get() else "",
                "--taxii" if self.taxii.get() else "",
                "--collection", "default",
                "--user", "user",
                "--password", "pass"
            ]
            self.run_command(" ".join(filter(None, stix_cmd)))

        if self.module_choice.get() in ["pcap_export", "both"]:
            pcap_cmd = [
                cmd_base, "modules/firmware_pcap_export.py",
                "--pcap", file_arg,
                "--chain-stix" if self.dashboard.get() else ""
            ]
            self.run_command(" ".join(filter(None, pcap_cmd)))

    def run_command(self, cmd):
        self.output_box.insert(tk.END, f"> Running: {cmd}\n\n")
        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
            self.output_box.insert(tk.END, stdout.decode())
            if stderr:
                self.output_box.insert(tk.END, f"\n[ERROR]\n{stderr.decode()}")
        except Exception as e:
            self.output_box.insert(tk.END, f"\n[Exception] {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirmwareGUI(root)
    root.mainloop()
