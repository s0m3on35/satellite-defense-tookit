#!/usr/bin/env python3
# modules/analysis/firmware_cfg_exporter.py

import argparse
import os
from capstone import *
import networkx as nx
from pathlib import Path

def disassemble_firmware(firmware_path, arch="arm", base_addr=0x0):
    with open(firmware_path, "rb") as f:
        code = f.read()

    if arch == "arm":
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif arch == "x86":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        raise ValueError("Unsupported architecture.")

    md.detail = True
    instructions = list(md.disasm(code, base_addr))
    return instructions

def build_cfg(instructions):
    cfg = nx.DiGraph()
    for i, ins in enumerate(instructions):
        addr = ins.address
        cfg.add_node(addr, mnemonic=ins.mnemonic, op_str=ins.op_str)

        if "b" in ins.mnemonic or "j" in ins.mnemonic:
            if ins.op_str.startswith("0x"):
                try:
                    target = int(ins.op_str, 16)
                    cfg.add_edge(addr, target)
                except ValueError:
                    pass
        elif i + 1 < len(instructions):
            cfg.add_edge(addr, instructions[i + 1].address)
    return cfg

def export_cfg(cfg, output_path):
    nx.drawing.nx_pydot.write_dot(cfg, output_path)
    print(f"[+] Control Flow Graph exported to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Firmware CFG Exporter (Military-Grade)")
    parser.add_argument("-f", "--firmware", required=True, help="Path to firmware binary")
    parser.add_argument("-a", "--arch", default="arm", choices=["arm", "x86"], help="Target architecture")
    parser.add_argument("-o", "--output", required=True, help="Output .dot file path")
    parser.add_argument("--base", type=lambda x: int(x, 16), default=0x0, help="Base address for disassembly")
    args = parser.parse_args()

    insns = disassemble_firmware(args.firmware, args.arch, args.base)
    cfg = build_cfg(insns)
    export_cfg(cfg, args.output)

if __name__ == "__main__":
    main()
