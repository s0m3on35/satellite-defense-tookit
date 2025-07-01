# modules/analysis/payload_emulator.py
import subprocess
import argparse
import os

def emulate_binary_qemu(binary_path):
    print(f"[+] Emulating {binary_path} via QEMU...")
    cmd = ["qemu-arm", "-L", "/usr/arm-linux-gnueabi", binary_path]
    subprocess.call(cmd)

def emulate_binary_docker(binary_path):
    print(f"[+] Emulating {binary_path} in Docker sandbox...")
    os.makedirs("sandbox", exist_ok=True)
    os.system(f"cp {binary_path} sandbox/")
    subprocess.call([
        "docker", "run", "--rm", "-v", f"{os.getcwd()}/sandbox:/sandbox", 
        "debian", "/sandbox/" + os.path.basename(binary_path)
    ])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True, help="Path to firmware or ELF binary")
    parser.add_argument("--mode", choices=["qemu", "docker"], default="qemu", help="Emulation method")
    args = parser.parse_args()

    if args.mode == "qemu":
        emulate_binary_qemu(args.bin)
    else:
        emulate_binary_docker(args.bin)
