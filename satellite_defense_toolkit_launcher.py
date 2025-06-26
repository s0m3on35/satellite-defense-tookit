
#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime

MODULES = {
    "1": ("GNSS AI Anomaly Detector", "modules/gnss_ai_anomaly_detector.py"),
    "2": ("RF Jammer Locator", "modules/rf_jammer_locator.py"),
    "3": ("Firmware Watcher Agent", "modules/firmware_watcher_agent.py"),
    "4": ("Telemetry LSTM Monitor", "modules/telemetry_lstm_monitor.py"),
}

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def run_script(script_path):
    if os.path.exists(script_path):
        log(f"Launching {script_path}")
        subprocess.run(["python3", script_path])
    else:
        log(f"Script not found: {script_path}")

def main():
    while True:
        print("""
==============================
🛰️ Satellite Defense Toolkit
==============================
1. GNSS AI Anomaly Detector
2. RF Jammer Locator
3. Firmware Watcher Agent
4. Telemetry LSTM Monitor
5. Exit
""")

        choice = input("Choose a module [1-5]: ").strip()
        if choice in MODULES:
            run_script(MODULES[choice][1])
        elif choice == "5":
            log("Exiting...")
            break
        else:
            log("Invalid choice.")

if __name__ == "__main__":
    main()
