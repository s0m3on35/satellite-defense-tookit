
#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")

def run_script(script_name):
    log(f"Launching {script_name}...")
    script_path = os.path.join("satellite_defense_toolkit", script_name)
    if os.path.exists(script_path):
        subprocess.run(["python3", script_path])
    else:
        log(f"Script not found: {script_path}")

def main():
    while True:
        print("""
==========================================
   🛰️ Advanced Satellite Defense Toolkit
==========================================

Select a module to execute:

1. GNSS AI Anomaly Detector
2. RF Jammer Locator
3. Firmware Watcher Agent
4. Telemetry LSTM Monitor
5. Exit
""")

        choice = input("Enter your choice [1-5]: ").strip()

        if choice == '1':
            run_script("gnss_ai_anomaly_detector.py")
        elif choice == '2':
            run_script("rf_jammer_locator.py")
        elif choice == '3':
            run_script("firmware_watcher_agent.py")
        elif choice == '4':
            run_script("telemetry_lstm_monitor.py")
        elif choice == '5':
            log("Exiting toolkit.")
            break
        else:
            print("Invalid option. Please choose 1-5.")

if __name__ == "__main__":
    main()
