#!/usr/bin/env python3
# Route: satellite_defense_toolkit_gui.py

import tkinter as tk
from tkinter import ttk, filedialog
import subprocess
import threading
import os
import json
import time
import websocket

DASHBOARD_WS_URL = "ws://localhost:8765"

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
    "Forensics": {
        "Firmware Timeline Builder": "modules/forensics/firmware_timeline_builder.py",
        "Memwatch Agent": "modules/forensics/memwatch_agent.py",
        "OTA Packet Analyzer": "modules/forensics/ota_packet_analyzer.py"
    },
    "Advanced Analysis": {
        "Binary Diff Engine": "modules/analysis/binary_diff_engine.py",
        "ELF Section Analyzer": "modules/analysis/elf_section_analyzer.py",
        "Firmware CFG Exporter": "modules/analysis/firmware_cfg_exporter.py",
        "Firmware Obfuscation Classifier": "modules/analysis/firmware_obfuscation_classifier.py",
        "Firmware Recovery Toolkit": "modules/analysis/firmware_recovery_toolkit.py",
        "Heap/Stack Pattern Scanner": "modules/analysis/heap_stack_pattern_scanner.py",
        "Syscall Extractor": "modules/analysis/syscall_extractor.py",
        "Dynamic String Decoder": "modules/analysis/dynamic_string_decoder.py",
        "Forensic Event Correlator": "modules/analysis/forensic_event_correlator.py"
    },
    "Firmware": {
        "Firmware Crypto Auditor": "modules/firmware/firmware_crypto_auditor.py",
        "Firmware PCAP Export": "modules/firmware/firmware_pcap_export.py",
        "Firmware STIX Export": "modules/firmware/firmware_stix_export.py",
        "Firmware Unpacker": "modules/firmware/firmware_unpacker.py",
        "Firmware Watcher Agent": "modules/firmware/firmware_watcher_agent.py",
        "Firmware Backdoor Scanner": "modules/firmware/firmware_backdoor_scanner.py"
    },
    "Attacks": {
        "Firmware Persistent Implant": "modules/attacks/firmware_persistent_implant.py",
        "GNSS Spoofer": "modules/attacks/gnss_spoofer.py",
        "OTA Firmware Injector": "modules/attacks/ota_firmware_injector.py",
        "Payload Launcher": "modules/attacks/payload_launcher.py",
        "RF Jammer DoS": "modules/attacks/rf_jammer_dos.py",
        "SATCOM C2 Hijacker": "modules/attacks/satcom_c2_hijacker.py",
        "Satellite Dish Aim Override": "modules/attacks/satellite_dish_aim_override.py",
        "Telemetry Data Spoofer": "modules/attacks/telemetry_data_spoofer.py"
    },
    "Analysis & AI": {
        "Entropy Analyzer": "modules/analysis/entropy_analyzer.py",
        "Entropy Analyzer GUI": "modules/analysis/entropy_analyzer_gui.py",
        "Entropy STIX Chain": "modules/analysis/entropy_stix_chain.py",
        "Payload Emulator": "modules/analysis/payload_emulator.py",
        "YARA Firmware Scanner": "modules/analysis/yara_firmware_scanner.py",
        "YARA Mapper": "modules/analysis/yara_mapper.py",
        "YARA STIX Exporter": "modules/analysis/yara_stix_exporter.py",
        "Threat Classifier AI": "modules/ai/threat_classifier.py",
        "AI Copilot Engine": "modules/copilot/copilot_ai.py"
    },
    "Telemetry & GNSS": {
        "GNSS AI Anomaly Detector": "modules/gnss_ai_anomaly_detector.py",
        "Telemetry LSTM Monitor": "modules/telemetry_lstm_monitor.py",
        "GNSS Spoofer Simulator": "modules/simulation/gnss_spoofer_sim.py"
    },
    "C2 & Dashboard": {
        "Agent Commander": "modules/c2/agent_commander.py",
        "Agent Fingerprint Logger": "modules/c2/agent_fingerprint_logger.py",
        "Dashboard WS Server": "modules/webgui/dashboard_ws_server.py",
        "MITRE Tracker": "modules/webgui/mitre_tracker.py",
        "Playback Panel": "modules/webgui/playback_panel.py",
        "WS Live Dashboard": "modules/visualization/ws_live_dashboard.py"
    },
    "Threat Intel & Visualization": {
        "MITRE Mapper": "modules/mitre_mapper.py",
        "Threat Feed Watcher": "modules/threat_feed_watcher.py",
        "STIX Threat Matcher": "modules/threat/stix_threat_matcher.py",
        "Zero-Day Mapper": "modules/intel/zero_day_mapper.py",
        "MapView Dashboard": "modules/visualization/mapview_dashboard.py",
        "Event Visualizer": "modules/visualization/event_visualizer.py",
        "Attack Frequency Heatmap": "modules/stats/attack_frequency_heatmap.py"
    }
}

class SatelliteDefenseToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Satellite Defense Toolkit")
        self.root.geometry("1050x720")
        self.root.configure(bg="#0f0f0f")

        self.ws = None
        self.connect_to_websocket()

        self.tab_control = ttk.Notebook(self.root)
        self.module_listboxes = {}

        for category, modules in MODULE_GROUPS.items():
            tab = ttk.Frame(self.tab_control)
            self.tab_control.add(tab, text=category)
            listbox = tk.Listbox(tab, font=("Courier", 11), width=80, height=25, bg="black", fg="lime", selectbackground="#444")
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

    def connect_to_websocket(self):
        try:
            self.ws = websocket.create_connection(DASHBOARD_WS_URL, timeout=3)
            self.send_dashboard_event("gui_online", "GUI launched")
        except Exception as e:
            self.log(f"[WebSocket] Offline: {e}")

    def send_dashboard_event(self, evt_type, msg):
        if self.ws:
            try:
                self.ws.send(json.dumps({"timestamp": time.time(), "type": evt_type, "message": msg}))
            except:
                self.ws = None

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
        self.log(f"[+] Running {name}")
        self.send_dashboard_event("module_run", f"{name} launched")
        threading.Thread(target=self.run_script, args=(path, name), daemon=True).start()

    def run_script(self, script, name):
        try:
            proc = subprocess.Popen(["python3", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                self.log(f"[{name}] {line.strip()}")
        except Exception as e:
            self.log(f"[Exception] {name} failed: {e}")

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

if __name__ == "__main__":
    root = tk.Tk()
    app = SatelliteDefenseToolkitGUI(root)
    root.mainloop()
