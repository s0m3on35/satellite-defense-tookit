
import argparse
import hashlib
import os
import time
import logging
import yaml
from datetime import datetime

# === Config & Logging ===
def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def setup_logging(log_path):
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

# === Core Logic ===
def compute_hash(filepath, algo='sha256'):
    h = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def monitor_firmware(file_path, expected_hash, interval, algo):
    logging.info(f"Monitoring firmware at {file_path} every {interval}s")
    while True:
        if not os.path.exists(file_path):
            logging.warning("Firmware file not found!")
        else:
            hash_now = compute_hash(file_path, algo)
            logging.info(f"Current {algo} hash: {hash_now}")
            if hash_now != expected_hash:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "file": file_path,
                    "expected": expected_hash,
                    "found": hash_now,
                    "alert": "HASH_MISMATCH"
                }
                os.makedirs("results", exist_ok=True)
                with open("results/firmware_alert.json", "w") as f:
                    f.write(str(alert))
                logging.error("Firmware hash mismatch! Potential tampering.")
                break
        time.sleep(interval)

# === Main ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)

    firmware_file = config['firmware_path']
    expected_hash = config['expected_hash']
    interval = config.get('interval', 10)
    algo = config.get('hash_algo', 'sha256')

    monitor_firmware(firmware_file, expected_hash, interval, algo)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Watcher Agent")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/firmware_watcher.log", help="Log file path")
    args = parser.parse_args()
    main(args)
