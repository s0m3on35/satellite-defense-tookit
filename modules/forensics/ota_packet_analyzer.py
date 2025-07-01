# modules/forensics/ota_packet_analyzer.py

import os
import json
import re
import subprocess
import sys
from datetime import datetime

# Dependency check/install
REQUIRED = ["scapy", "tqdm"]
subprocess.call([sys.executable, "-m", "pip", "install", *REQUIRED], stdout=subprocess.DEVNULL)

from scapy.all import rdpcap, Raw
from tqdm import tqdm

PCAP_DIR = "pcap_inputs/"
SIG_CONFIG = "config/ota_signatures.json"
LOG_DIR = "logs/ota_analysis/"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs("config", exist_ok=True)

DEFAULT_SIGS = {
    "OTA_START_MAGIC": "OTA_BEGIN",
    "Firmware_Binary": "firmware_v[0-9]+\\.[0-9]+",
    "Bootloader_Signature": "U\\xAA\\x55U\\xAA",
    "ELF_Header": "\\x7fELF"
}

def generate_default_signatures():
    if not os.path.exists(SIG_CONFIG):
        print("[+] No signature config found. Generating default...")
        with open(SIG_CONFIG, "w") as f:
            json.dump(DEFAULT_SIGS, f, indent=2)

def load_signatures():
    with open(SIG_CONFIG, "r") as f:
        return json.load(f)

def analyze_pcap(file_path, signatures, verbose=False):
    results = []
    packets = rdpcap(file_path)
    for pkt in tqdm(packets, desc=f"Scanning {os.path.basename(file_path)}", unit="pkt"):
        if Raw in pkt:
            payload = pkt[Raw].load
            for name, pattern in signatures.items():
                if re.search(pattern.encode(), payload):
                    entry = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "match": name,
                        "pattern": pattern,
                        "packet_summary": str(pkt.summary()),
                        "source": pkt[0].src if hasattr(pkt[0], 'src') else "N/A",
                        "destination": pkt[0].dst if hasattr(pkt[0], 'dst') else "N/A"
                    }
                    if verbose:
                        print(f"[+] Match: {name} | {pkt.summary()}")
                    results.append(entry)
    return results

def save_results(pcap_name, results):
    if results:
        out_file = os.path.join(LOG_DIR, f"{pcap_name}_ota_analysis.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Saved {len(results)} matches to {out_file}")
    else:
        print(f"[-] No matches found in {pcap_name}")

def main(verbose=False):
    print("[*] OTA Packet Analyzer - REDOT Forensics Module")
    generate_default_signatures()
    signatures = load_signatures()

    for fname in os.listdir(PCAP_DIR):
        if fname.endswith(".pcap") or fname.endswith(".pcapng"):
            fpath = os.path.join(PCAP_DIR, fname)
            matches = analyze_pcap(fpath, signatures, verbose=verbose)
            save_results(os.path.splitext(fname)[0], matches)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OTA Packet Analyzer")
    parser.add_argument("--verbose", action="store_true", help="Print matches live")
    args = parser.parse_args()
    main(verbose=args.verbose)
