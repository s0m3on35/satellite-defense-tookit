#!/usr/bin/env python3
# modules/analysis/firmware_obfuscation_classifier.py

import argparse
import os
import math
import json
import hashlib
from capstone import *
from pathlib import Path

WINDOW_SIZE = 4096

def calc_entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    probs = [f / len(data) for f in freq if f > 0]
    return -sum(p * math.log2(p) for p in probs)

def classify_entropy(entropy):
    if entropy > 7.5:
        return "High (Likely Encrypted/Packed)"
    elif entropy > 6.0:
        return "Moderate (Possibly Compressed/Encoded)"
    else:
        return "Low (Likely Code/Data)"

def analyze_firmware(firmware_path, output_path):
    with open(firmware_path, "rb") as f:
        firmware = f.read()

    results = []
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False

    for offset in range(0, len(firmware), WINDOW_SIZE):
        chunk = firmware[offset:offset + WINDOW_SIZE]
        entropy = calc_entropy(chunk)
        entropy_class = classify_entropy(entropy)
        disasm_count = len(list(md.disasm(chunk, offset)))

        rating = "Suspicious" if entropy > 7.5 or disasm_count < 10 else "Normal"

        result = {
            "offset": hex(offset),
            "entropy": round(entropy, 4),
            "entropy_class": entropy_class,
            "disasm_instr_count": disasm_count,
            "rating": rating,
            "sha256": hashlib.sha256(chunk).hexdigest()
        }
        results.append(result)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Analysis complete. Report saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Obfuscation Classifier")
    parser.add_argument("-f", "--firmware", required=True, help="Path to firmware binary")
    parser.add_argument("-o", "--output", required=True, help="Output JSON report path")
    args = parser.parse_args()

    analyze_firmware(args.firmware, args.output)
