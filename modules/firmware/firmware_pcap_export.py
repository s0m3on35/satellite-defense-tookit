import os
import logging
import subprocess
import datetime
import pyshark  # or scapy
import yara

# === Setup ===
LOG_FILE = "logs/firmware_pcap.log"
RESULTS_DIR = "results"
PCAP_DIR = "pcap_samples"
FIRMWARE_DUMP = "results/extracted_from_pcap.bin"

def setup_logging():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger().addHandler(logging.StreamHandler())

# === Extract payload from PCAP (simple example) ===
def extract_payload(pcap_file, output_file):
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="data")
        with open(output_file, 'wb') as f:
            for pkt in cap:
                if hasattr(pkt, 'data'):
                    raw = bytes.fromhex(pkt.data.data.replace(':', ''))
                    f.write(raw)
        logging.info(f"Payload extracted to {output_file}")
        return True
    except Exception as e:
        logging.error(f"Payload extraction failed: {e}")
        return False

# === YARA Scan ===
def yara_scan(file_path, rules_path="rules/firmware_rules.yar"):
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)
        if matches:
            logging.warning(f"YARA match: {matches}")
            return True
        return False
    except Exception as e:
        logging.error(f"YARA scan error: {e}")
        return False

# === Chain to STIX Export ===
def chain_to_stix(firmware_file):
    try:
        subprocess.run([
            "python3",
            "modules/firmware/firmware_stix_export.py",
            "--firmware", firmware_file,
            "--dashboard",
            "--log", "logs/firmware_stix.log"
        ], check=True)
        logging.info("STIX export module successfully chained.")
    except subprocess.CalledProcessError as e:
        logging.error(f"STIX export failed: {e}")

# === Main ===
def process_pcap(pcap_file):
    logging.info(f"Processing PCAP: {pcap_file}")
    if extract_payload(pcap_file, FIRMWARE_DUMP):
        if yara_scan(FIRMWARE_DUMP):
            chain_to_stix(FIRMWARE_DUMP)
        else:
            logging.info("No YARA anomalies detected.")
    else:
        logging.info("No valid payload extracted.")

if __name__ == "__main__":
    setup_logging()
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(PCAP_DIR, exist_ok=True)

    # Example: scan all pcap files in folder
    for file in os.listdir(PCAP_DIR):
        if file.endswith(".pcap"):
            process_pcap(os.path.join(PCAP_DIR, file))
