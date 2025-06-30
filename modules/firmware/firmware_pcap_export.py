import argparse
import os
import logging
import datetime
import json
import subprocess
from scapy.all import sniff, wrpcap, Raw
from collections import Counter
import websocket

# === CONFIG & LOGGING ===
def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

# === LIVE WEBSOCKET STREAMING ===
def stream_ws_dashboard(event, data):
    try:
        ws = websocket.create_connection("ws://localhost:8080/ws/metrics")
        ws.send(json.dumps({"event": event, "data": data}))
        ws.close()
    except Exception as e:
        logging.warning(f"WebSocket stream failed: {e}")

# === PCAP SIGNATURE MATCHING ===
def check_signatures(packets):
    sig_hits = []
    ioc_keywords = [b'telnet', b'dropbear', b'reverse', b'cmd.exe', b'/bin/sh']
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.lower()
            for sig in ioc_keywords:
                if sig in payload:
                    sig_hits.append(sig.decode())
    return list(set(sig_hits))

# === CAPTURE ===
def capture_packets(interface, duration, output_dir):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(output_dir, f"firmware_capture_{ts}.pcap")
    logging.info(f"Capturing on {interface} for {duration}s")
    packets = sniff(iface=interface, timeout=duration)
    wrpcap(pcap_file, packets)
    logging.info(f"Saved {len(packets)} packets to {pcap_file}")
    return pcap_file, packets

# === SURICATA / ZEEK ===
def run_suricata(pcap_path, output_dir):
    try:
        os.makedirs(output_dir, exist_ok=True)
        subprocess.run(["suricata", "-r", pcap_path, "-l", output_dir], check=True)
        alert_path = os.path.join(output_dir, "fast.log")
        if os.path.exists(alert_path):
            with open(alert_path, 'r') as f:
                alerts = f.read()
                logging.info(f"Suricata alerts:\n{alerts}")
                return alerts
    except Exception as e:
        logging.warning(f"Suricata failed: {e}")
    return ""

def run_zeek(pcap_path, output_dir):
    try:
        os.makedirs(output_dir, exist_ok=True)
        subprocess.run(["zeek", "-r", pcap_path], cwd=output_dir, check=True)
        return True
    except Exception as e:
        logging.warning(f"Zeek failed: {e}")
        return False

# === MAIN ===
def main(args):
    os.makedirs(args.output, exist_ok=True)
    setup_logging(args.log)

    pcap_file, packets = capture_packets(args.interface, args.duration, args.output)

    # === PCAP Signature Match
    sigs = check_signatures(packets)
    stream_ws_dashboard("signature_alerts", {"matches": sigs})

    # === Protocol distribution
    protocols = [pkt.name for pkt in packets]
    proto_count = dict(Counter(protocols))
    stream_ws_dashboard("protocol_distribution", proto_count)

    # === Suricata & Zeek
    alerts = run_suricata(pcap_file, args.output + "/suricata")
    stream_ws_dashboard("suricata_alerts", {"alerts": alerts})

    zeek_ok = run_zeek(pcap_file, args.output + "/zeek")
    stream_ws_dashboard("zeek_status", {"result": "success" if zeek_ok else "failure"})

    # === Trigger Correlation Engine
    subprocess.run(["python3", "modules/firmware/firmware_stix_export.py",
                    "--firmware", pcap_file,
                    "--log", "logs/firmware_stix_from_pcap.log"], check=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Firmware PCAP Capture & Analysis")
    parser.add_argument("--interface", default="eth0", help="Capture interface")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("--output", default="results", help="Output dir")
    parser.add_argument("--log", default="logs/firmware_pcap_export.log", help="Log file path")
    args = parser.parse_args()
    main(args)
