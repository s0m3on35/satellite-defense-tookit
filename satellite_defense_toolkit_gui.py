
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import subprocess
import os
import threading

MODULES = {
    "GNSS Spoof Detector": "modules/gnss/gnss_ai_anomaly_detector.py",
    "RF Jammer Locator": "modules/rf/rf_jammer_locator.py",
    "Firmware Watcher": "modules/firmware/firmware_watcher_agent.py",
    "Telemetry Anomaly Monitor": "modules/telemetry/telemetry_lstm_monitor.py",
    "STIX Exporter": "modules/stix/firmware_stix_export.py",
    "YARA → STIX Exporter": "modules/stix/yara_stix_exporter.py",
    "Firewall Rule Generator": "modules/defense/firewall_rule_generator.py",
    "Firmware CVE Mapper": "modules/intel/firmware_cve_mapper.py",
    "Attack Heatmap Generator": "modules/stats/attack_frequency_heatmap.py",
    "Timeline Builder": "modules/forensics/firmware_timeline_builder.py",
    "Agent Commander": "modules/c2/agent_commander.py"
}

class SatelliteDefenseGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Satellite Defense Toolkit GUI")
        self.root.geometry("950x650")
        self.create_widgets()

    def create_widgets(self):
        title = ttk.Label(self.root, text="Satellite Defense Toolkit", font=("Helvetica", 18, "bold"))
        title.pack(pady=10)

        self.module_listbox = tk.Listbox(self.root, height=15, font=("Courier", 11), selectmode=tk.SINGLE)
        for module in MODULES:
            self.module_listbox.insert(tk.END, module)
        self.module_listbox.pack(pady=5, padx=10, fill=tk.BOTH, expand=False)

        run_button = ttk.Button(self.root, text="Run Selected Module", command=self.run_selected_module)
        run_button.pack(pady=5)

        save_button = ttk.Button(self.root, text="Save Log", command=self.save_log)
        save_button.pack(pady=5)

        clear_button = ttk.Button(self.root, text="Clear Log", command=self.clear_output)
        clear_button.pack(pady=5)

        self.output_console = scrolledtext.ScrolledText(self.root, height=20, wrap=tk.WORD, font=("Courier", 10))
        self.output_console.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def run_selected_module(self):
        selection = self.module_listbox.curselection()
        if not selection:
            self.append_output("No module selected.\n")
            return
        module_name = self.module_listbox.get(selection[0])
        module_path = MODULES.get(module_name)
        if not os.path.exists(module_path):
            self.append_output(f"Module not found: {module_path}\n")
            return
        self.append_output(f"Running: {module_name}...\n")
        threading.Thread(target=self.execute_module, args=(module_path,), daemon=True).start()

    def execute_module(self, path):
        try:
            process = subprocess.Popen(["python3", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(process.stdout.readline, ''):
                self.append_output(line)
            process.stdout.close()
            process.wait()
        except Exception as e:
            self.append_output(f"Error running module: {e}\n")

    def append_output(self, text):
        self.output_console.insert(tk.END, text)
        self.output_console.see(tk.END)

    def save_log(self):
        log_data = self.output_console.get(1.0, tk.END)
        filepath = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log Files", "*.log")])
        if filepath:
            with open(filepath, "w") as f:
                f.write(log_data)
            self.append_output(f"Log saved to: {filepath}\n")

    def clear_output(self):
        self.output_console.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SatelliteDefenseGUI(root)
    root.mainloop()
