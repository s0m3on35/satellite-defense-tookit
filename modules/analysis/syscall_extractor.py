#!/usr/bin/env python3
# modules/analysis/syscall_extractor.py

import argparse
import json
import logging
from capstone import *
from pathlib import Path
from collections import Counter

# Mapping of syscall numbers (ARM EABI or INT codes) to MITRE ATT&CK tactics
MITRE_MAP = {
    "0x01": "T1059 (Command Execution)",
    "0x02": "T1003 (Credential Dumping)",
    "0x3c": "T1027 (Obfuscated Files or Information)",
    "0x5a": "T1055 (Process Injection)",
    "0x66": "T1071 (Application Layer Protocol)",
    "0x69": "T1040 (Network Sniffing)",
    "0x6e": "T1105 (Remote File Copy)",
    "0x72": "T1082 (System Information Discovery)",
}

def setup_logger(output_dir):
    log_file = Path(output_dir) / "syscall_extractor.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    logging.info("Syscall extraction started.")

def extract_syscalls(firmware_path, arch="arm"):
    with open(firmware_path, "rb") as f:
        firmware = f.read()

    if arch == "arm":
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif arch == "x86":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        raise ValueError("Unsupported architecture: choose 'arm' or 'x86'")

    syscalls = []
    syscall_counter = Counter()

    for insn in md.disasm(firmware, 0x0):
        if insn.mnemonic in ["svc", "int"] and "0x" in insn.op_str:
            syscall_num = insn.op_str.strip().lower()
            mitre = MITRE_MAP.get(syscall_num, "Unknown")
            syscall_counter[syscall_num] += 1
            syscalls.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "operand": syscall_num,
                "mapped_tactic": mitre
            })
            logging.info(f"Found syscall at {hex(insn.address)}: {syscall_num} → {mitre}")

    return syscalls, syscall_counter

def save_report(syscalls, freq_counter, output_path):
    report = {
        "total_syscalls": len(syscalls),
        "unique_syscalls": len(freq_counter),
        "top_syscalls": freq_counter.most_common(10),
        "details": syscalls
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Syscall report saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Military-Grade Firmware Syscall Extractor and MITRE ATT&CK Mapper")
    parser.add_argument("-f", "--firmware", required=True, help="Path to firmware binary")
    parser.add_argument("-a", "--arch", default="arm", choices=["arm", "x86"], help="Firmware architecture")
    parser.add_argument("-o", "--output", required=True, help="Output JSON report path")
    args = parser.parse_args()

    output_dir = Path(args.output).parent
    setup_logger(output_dir)

    syscalls, freq = extract_syscalls(args.firmware, args.arch)
    save_report(syscalls, freq, args.output)
    logging.info("Syscall extraction completed.")

if __name__ == "__main__":
    main()
