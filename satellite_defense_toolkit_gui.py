#!/usr/bin/env python3
# File: satellite_defense_toolkit_gui.py

import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
import subprocess, threading, os, json, time
import websocket

DASHBOARD_WS_URL = "ws://localhost:8765"
AUDIT_TRAIL_LOG = "logs/audit_trail.jsonl"

MODULE_GROUPS = {
    "Uncategorized": {
        "Firmware Backdoor Scanner": "modules/firmware_backdoor_scanner.py",
        "Firmware Unpacker": "modules/firmware_unpacker.py",
        "Firmware Watcher Agent": "modules/firmware_watcher_agent.py",
        "Gnss Ai Anomaly Detector": "modules/gnss_ai_anomaly_detector.py",
        "Mitre Mapper": "modules/mitre_mapper.py",
        "Rf Jammer Locator": "modules/rf_jammer_locator.py",
        "Satcom C2 Spoof Detector": "modules/satcom_c2_spoof_detector.py",
        "Telemetry Lstm Monitor": "modules/telemetry_lstm_monitor.py",
        "Threat Feed Watcher": "modules/threat_feed_watcher.py",
    },
    "Ai": {
        "Ai Rule Generator": "modules/ai/ai_rule_generator.py",
        "Gpt Log Intelligence": "modules/ai/gpt_log_intelligence.py",
        "Gpt Remote Analyzer": "modules/ai/gpt_remote_analyzer.py",
        "Telemetry Anomaly Predictor": "modules/ai/telemetry_anomaly_predictor.py",
        "Threat Classifier": "modules/ai/threat_classifier.py",
        "Threat Summary Llm": "modules/ai/threat_summary_llm.py",
    },
    "Analysis": {
        "Binary Diff Engine": "modules/analysis/binary_diff_engine.py",
        "Dynamic String Decoder": "modules/analysis/dynamic_string_decoder.py",
        "Elf Section Analyzer": "modules/analysis/elf_section_analyzer.py",
        "Entropy Analyzer": "modules/analysis/entropy_analyzer.py",
        "Entropy Analyzer Gui": "modules/analysis/entropy_analyzer_gui.py",
        "Entropy Stix Chain": "modules/analysis/entropy_stix_chain.py",
        "Firmware Cfg Exporter": "modules/analysis/firmware_cfg_exporter.py",
        "Firmware Obfuscation Classifier": "modules/analysis/firmware_obfuscation_classifier.py",
        "Firmware Recovery Toolkit": "modules/analysis/firmware_recovery_toolkit.py",
        "Forensic Event Correlator": "modules/analysis/forensic_event_correlator.py",
        "Heap Stack Pattern Scanner": "modules/analysis/heap_stack_pattern_scanner.py",
        "Payload Emulator": "modules/analysis/payload_emulator.py",
        "Syscall Extractor": "modules/analysis/syscall_extractor.py",
        "Yara Firmware Scanner": "modules/analysis/yara_firmware_scanner.py",
        "Yara Mapper": "modules/analysis/yara_mapper.py",
        "Yara Stix Exporter": "modules/analysis/yara_stix_exporter.py",
    },
    "Attacks": {
        "Firmware Persistent Implant": "modules/attacks/firmware_persistent_implant.py",
        "Gnss Spoofer": "modules/attacks/gnss_spoofer.py",
        "Ota Firmware Injector": "modules/attacks/ota_firmware_injector.py",
        "Payload Launcher": "modules/attacks/payload_launcher.py",
        "Rf Jammer Dos": "modules/attacks/rf_jammer_dos.py",
        "Satcom C2 Hijacker": "modules/attacks/satcom_c2_hijacker.py",
        "Satellite Dish Aim Override": "modules/attacks/satellite_dish_aim_override.py",
        "Self Compiling Dropper": "modules/attacks/self_compiling_dropper.py",
        "Telemetry Data Spoofer": "modules/attacks/telemetry_data_spoofer.py",
    },
    "C2": {
        "Agent Commander": "modules/c2/agent_commander.py",
        "Agent Fingerprint Logger": "modules/c2/agent_fingerprint_logger.py",
        "Agent Receiver": "modules/c2/agent_receiver.py",
    },
    "Copilot": {
        "Copilot Ai": "modules/copilot/copilot_ai.py",
    },
    "Dashboard": {
        "Yara Dashboard Streamer": "modules/dashboard/yara_dashboard_streamer.py",
    },
    "Defense": {
        "Binary Integrity Watcher": "modules/defense/binary_integrity_watcher.py",
        "Firewall Rule Generator": "modules/defense/firewall_rule_generator.py",
        "Firmware Integrity Watcher": "modules/defense/firmware_integrity_watcher.py",
        "Firmware Memory Shield": "modules/defense/firmware_memory_shield.py",
        "Firmware Rollback Protector": "modules/defense/firmware_rollback_protector.py",
        "Firmware Signature Validator": "modules/defense/firmware_signature_validator.py",
        "Gnss Spoof Guard": "modules/defense/gnss_spoof_guard.py",
        "Interface Integrity Monitor": "modules/defense/interface_integrity_monitor.py",
        "Kernel Module Guard": "modules/defense/kernel_module_guard.py",
        "Live Integrity Watcher": "modules/defense/live_integrity_watcher.py",
        "Ota Guard": "modules/defense/ota_guard.py",
        "Ota Stream Guard": "modules/defense/ota_stream_guard.py",
        "Rf Injection Barrier": "modules/defense/rf_injection_barrier.py",
        "Secure Update Guard": "modules/defense/secure_update_guard.py",
        "System Call Anomaly Watcher": "modules/defense/system_call_anomaly_watcher.py",
        "Telemetry Guardian": "modules/defense/telemetry_guardian.py",
    },
    "Firmware": {
        "Firmware Crypto Auditor": "modules/firmware/firmware_crypto_auditor.py",
        "Firmware Pcap Export": "modules/firmware/firmware_pcap_export.py",
        "Firmware Stix Export": "modules/firmware/firmware_stix_export.py",
        "Ota Stream Monitor": "modules/firmware/ota_stream_monitor.py",
    },
    "Forensics": {
        "Firmware Timeline Builder": "modules/forensics/firmware_timeline_builder.py",
        "Flash Sector Dumper": "modules/forensics/flash_sector_dumper.py",
        "Memwatch Agent": "modules/forensics/memwatch_agent.py",
        "Ota Packet Analyzer": "modules/forensics/ota_packet_analyzer.py",
    },
    "Gui": {
        "Firmware Gui Trigger": "modules/gui/firmware_gui_trigger.py",
    },
    "Intel": {
        "Firmware Cve Mapper": "modules/intel/firmware_cve_mapper.py",
        "Zero Day Mapper": "modules/intel/zero_day_mapper.py",
    },
    "Simulation": {
        "Gnss Spoofer Sim": "modules/simulation/gnss_spoofer_sim.py",
    },
    "Stats": {
        "Attack Frequency Heatmap": "modules/stats/attack_frequency_heatmap.py",
    },
    "Threat": {
        "Stix Threat Matcher": "modules/threat/stix_threat_matcher.py",
    },
    "Visualization": {
        "Event Visualizer": "modules/visualization/event_visualizer.py",
        "Mapview Dashboard": "modules/visualization/mapview_dashboard.py",
        "Ws Live Dashboard": "modules/visualization/ws_live_dashboard.py",
    },
}

    "AI & Analysis": {
        "Threat Summary LLM": "modules/ai/threat_summary_llm.py",
        "Threat Classifier": "modules/ai/threat_classifier.py",
        "Copilot Engine": "modules/copilot/copilot_ai.py"
    },
    "Forensics": {
        "Firmware Timeline Builder": "modules/forensics/firmware_timeline_builder.py",
        "OTA Packet Analyzer": "modules/forensics/ota_packet_analyzer.py",
        "Memwatch Agent": "modules/forensics/memwatch_agent.py"
    },
    "Attacks": {
        "GNSS Spoofer": "modules/attacks/gnss_spoofer.py",
        "OTA Firmware Injector": "modules/attacks/ota_firmware_injector.py",
        "Firmware Persistent Implant": "modules/attacks/firmware_persistent_implant.py",
        "Payload Launcher": "modules/attacks/payload_launcher.py",
        "SATCOM C2 Hijacker": "modules/attacks/satcom_c2_hijacker.py"
    }
}

class SatelliteDefenseToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Satellite Defense Toolkit")
        self.root.geometry("1400x900")
        self.theme = "dark"
        self.ws = None
        self.run_history = []

        self.load_agents()
        self.connect_to_websocket()
        self.create_interface()

    def connect_to_websocket(self):
        try:
            self.ws = websocket.create_connection(DASHBOARD_WS_URL, timeout=2)
            self.send_dashboard_event("gui_online", "GUI initialized")
        except Exception as e:
            self.log(f"[WebSocket] Not connected: {e}")
            self.ws = None

    def send_dashboard_event(self, evt_type, msg):
        if self.ws:
            try:
                payload = {
                    "timestamp": time.time(),
                    "type": evt_type,
                    "message": msg,
                    "agent": self.agent_var.get()
                }
                self.ws.send(json.dumps(payload))
            except:
                self.ws = None

    def load_agents(self):
        self.agents = ["default"]
        try:
            with open("webgui/agents.json") as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.agents = [x["id"] for x in data if "id" in x]
        except:
            pass

    def create_interface(self):
        self.tab_control = ttk.Notebook(self.root)
        self.module_listboxes = {}

        topbar = tk.Frame(self.root, bg="#1a1a1a")
        topbar.pack(fill=tk.X)

        self.agent_var = tk.StringVar(value=self.agents[0])
        agent_dropdown = ttk.Combobox(topbar, textvariable=self.agent_var, values=self.agents, width=30)
        agent_dropdown.pack(side=tk.LEFT, padx=10, pady=5)

        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.search_modules)
        search_entry = tk.Entry(topbar, textvariable=self.search_var, font=("Courier", 12), width=40)
        search_entry.pack(side=tk.LEFT, padx=5)

        self.theme_button = tk.Button(topbar, text="Toggle Theme", command=self.toggle_theme)
        self.theme_button.pack(side=tk.RIGHT, padx=10)

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

    def toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"
        bg, fg = ("white", "black") if self.theme == "light" else ("black", "lime")
        self.root.configure(bg=bg)
        self.output.configure(bg=bg, fg=fg)

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
            "event": "execution",
            "agent": self.agent_var.get()
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
            self.log(f"[â] Saved to {path}")

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
