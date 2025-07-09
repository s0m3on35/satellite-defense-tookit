#!/usr/bin/env python3
# modules/analysis/dynamic_string_decoder.py

import argparse
import base64
import codecs
import re
import json
from pathlib import Path

XOR_KEYS = [0x20, 0x55, 0xAA, 0xFF]

def extract_ascii_strings(blob, min_len=4):
    pattern = re.compile(rb'[ -~]{%d,}' % min_len)
    return [m.group().decode(errors='ignore') for m in pattern.finditer(blob)]

def try_decode_b64(s):
    try:
        decoded = base64.b64decode(s).decode('utf-8')
        return decoded if all(32 <= ord(c) <= 126 for c in decoded) else None
    except Exception:
        return None

def try_decode_rot13(s):
    try:
        return codecs.decode(s, 'rot_13')
    except Exception:
        return None

def try_decode_xor(s, key):
    try:
        decoded = ''.join(chr(ord(c) ^ key) for c in s)
        if all(32 <= ord(c) <= 126 for c in decoded):
            return decoded
    except Exception:
        return None

def try_decode_hex(s):
    try:
        b = bytes.fromhex(s)
        if b and all(32 <= c <= 126 for c in b):
            return b.decode()
    except Exception:
        return None

def analyze_strings(strings):
    decoded_results = []
    for s in strings:
        result = {"original": s, "decodings": {}}

        b64 = try_decode_b64(s)
        if b64:
            result["decodings"]["base64"] = b64

        rot = try_decode_rot13(s)
        if rot and rot != s:
            result["decodings"]["rot13"] = rot

        hexed = try_decode_hex(s)
        if hexed:
            result["decodings"]["hex"] = hexed

        for k in XOR_KEYS:
            x = try_decode_xor(s, k)
            if x:
                result["decodings"][f"xor_0x{format(k, '02X')}"] = x

        if result["decodings"]:
            decoded_results.append(result)

    return decoded_results

def main():
    parser = argparse.ArgumentParser(description="Dynamic String Decoder for Obfuscated Firmware Payloads")
    parser.add_argument("-f", "--firmware", required=True, help="Path to firmware image")
    parser.add_argument("-o", "--output", required=True, help="Path to output decoded strings JSON report")
    parser.add_argument("--minlen", type=int, default=6, help="Minimum ASCII string length to extract")
    args = parser.parse_args()

    with open(args.firmware, "rb") as f:
        blob = f.read()

    ascii_strings = extract_ascii_strings(blob, args.minlen)
    decoded = analyze_strings(ascii_strings)

    with open(args.output, "w") as out:
        json.dump(decoded, out, indent=2)

    print(f"[+] Extracted {len(ascii_strings)} strings, {len(decoded)} decoded.")
    print(f"[+] Report saved to: {args.output}")

if __name__ == "__main__":
    main()
