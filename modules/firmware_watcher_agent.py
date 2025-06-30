import argparse, hashlib, os, time, json, requests
from datetime import datetime

CONFIG_PATH = "modules/config/config.yaml"
LOG_PATH = "logs/firmware_watcher.log"
ALERT_FILE = "webgui/alerts.json"
WEBHOOK = "http://127.0.0.1:9999/alert"
FIRMWARE_FILE = "modules/data/test_firmware.bin"
EXPECTED_HASH = "43ce11496e4375e5dcbcf9b75b82b8c3d9dad3f61ae8c9007f10d5b735545365"
INTERVAL = 10
ALGO = "sha256"
AGENT_ID = "firmware_watcher"

def compute_hash(filepath):
    h = hashlib.new(ALGO)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def push_alert(info):
    data = {
        "agent": AGENT_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "alert": "FIRMWARE_TAMPER_DETECTED",
        "details": info,
        "type": "firmware"
    }
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")
    try:
        requests.post(WEBHOOK, json=data, timeout=3)
    except:
        pass

def monitor():
    while True:
        if os.path.exists(FIRMWARE_FILE):
            current_hash = compute_hash(FIRMWARE_FILE)
            if current_hash != EXPECTED_HASH:
                alert = {
                    "expected": EXPECTED_HASH,
                    "found": current_hash,
                    "file": FIRMWARE_FILE
                }
                push_alert(alert)
                break
        time.sleep(INTERVAL)

if __name__ == "__main__":
    monitor()
