import os
import json
import logging
import argparse
from datetime import datetime
from scapy.all import sniff, wrpcap, Raw
import threading
import websocket
import subprocess
import hashlib
import uuid
import re

# === Setup ===
def setup_logging(log_file):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def generate_filename(prefix, ext="pcap"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"results/{prefix}_{timestamp}.{ext}"

def detect_anomaly(pkt):
    try:
        if Raw in pkt:
            payload = pkt[Raw].load.decode(errors="ignore")
            patterns = ["telnet", "dropbear", "firmware", "root:"]
            for p in patterns:
                if p in payload:
                    return p
    except Exception:
        pass
    return None

def yara_match(packet_data, yara_rules_path="rules/firmware.yar"):
    try:
        import yara
        rules = yara.compile(filepath=yara_rules_path)
        matches = rules.match(data=packet_data)
        if matches:
            return [str(m.rule) for m in matches]
    except Exception:
        return []
    return []

def send_websocket_alert(data):
    try:
        ws = websocket.create_connection("ws://localhost:8765")
        ws.send(json.dumps(data))
        ws.close()
        logging.info("[✓] WebSocket alert sent.")
    except Exception as e:
        logging.warning(f"[!] WebSocket failed: {e}")

def chain_to_stix(packet_file, match_data):
    from firmware_stix_export import create_stix_bundle, save_bundle
    hash_val = hashlib.sha256(open(packet_file, 'rb').read()).hexdigest()
    bundle = create_stix_bundle(
        pattern=match_data,
        hash_val=hash_val,
        filename=os.path.basename(packet_file),
        killchain_stage="command-and-control"
    )
    stix_path = packet_file.replace(".pcap", ".json")
    save_bundle(bundle, stix_path)
    return stix_path

# === Capture Logic ===
def start_capture(interface, count, timeout, output, chain_stix=False):
    os.makedirs("results", exist_ok=True)
    packets = []

    def process_packet(pkt):
        match = detect_anomaly(pkt)
        if match:
            logging.warning(f"[!] Anomaly Detected: {match}")
            alert = {
                "type": "firmware_pcap_anomaly",
                "match": match,
                "timestamp": datetime.utcnow().isoformat()
            }
            send_websocket_alert(alert)
            if chain_stix:
                chain_to_stix(output, match)
        raw_data = bytes(pkt)
        yara_hits = yara_match(raw_data)
        if yara_hits:
            logging.warning(f"[!] YARA Match: {yara_hits}")
            send_websocket_alert({
                "type": "yara_match",
                "rules": yara_hits,
                "timestamp": datetime.utcnow().isoformat()
            })
        packets.append(pkt)

    logging.info(f"[✓] Starting capture on {interface}")
    sniff(iface=interface, prn=process_packet, count=count, timeout=timeout)
    wrpcap(output, packets)
    logging.info(f"[✓] Saved PCAP to {output}")

# === Main ===
def main(args):
    setup_logging(args.log)
    output_file = generate_filename("firmware_capture", "pcap")
    start_capture(
        interface=args.iface,
        count=args.count,
        timeout=args.timeout,
        output=output_file,
        chain_stix=args.stix
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware PCAP Capture + STIX Export + YARA")
    parser.add_argument("--iface", default="eth0", help="Interface to sniff on")
    parser.add_argument("--count", type=int, default=0, help="Number of packets (0=unlimited)")
    parser.add_argument("--timeout", type=int, default=30, help="Time in seconds to run capture")
    parser.add_argument("--stix", action="store_true", help="Chain to STIX export")
    parser.add_argument("--log", default="logs/firmware_pcap.log", help="Log file path")
    args = parser.parse_args()
    main(args)
