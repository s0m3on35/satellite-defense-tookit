# core/security/airgap_mode.py
import socket
import os

def disable_outbound():
    print("[✓] Enabling airgap mode...")
    os.system("iptables -P OUTPUT DROP")
    os.system("iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT")
    os.system("iptables -A OUTPUT -d ::1 -j ACCEPT")

def enable_local_dns():
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write("nameserver 127.0.0.1\n")
        print("[✓] Local DNS enforced (127.0.0.1)")
    except PermissionError:
        print("[!] Permission denied for resolv.conf (run as root)")

def test_connectivity():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        print("[!] Internet connection still active")
    except:
        print("[✓] Airgap appears effective")

if __name__ == "__main__":
    disable_outbound()
    enable_local_dns()
    test_connectivity()
