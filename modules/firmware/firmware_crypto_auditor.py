# modules/firmware/firmware_crypto_auditor.py
import argparse
import re

WEAK_PATTERNS = [
    (rb"md5", "Weak hash: MD5"),
    (rb"rc4", "Weak cipher: RC4"),
    (rb"base64_decode", "Encoding misuse"),
    (rb"xor", "XOR obfuscation detected"),
    (rb"des_", "Weak cipher: DES"),
]

STRONG_PATTERNS = [
    (rb"aes", "AES encryption found"),
    (rb"rsa", "RSA keys present"),
    (rb"ecc", "Elliptic Curve Crypto found"),
    (rb"hmac", "HMAC authentication found"),
]

def scan_firmware_crypto(path):
    with open(path, 'rb') as f:
        data = f.read()
    findings = {"weak": [], "strong": []}
    for pattern, desc in WEAK_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            findings["weak"].append(desc)
    for pattern, desc in STRONG_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            findings["strong"].append(desc)

    trust_score = 100 - len(findings["weak"]) * 25
    return findings, max(0, trust_score)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", required=True, help="Firmware binary file")
    args = parser.parse_args()

    findings, score = scan_firmware_crypto(args.firmware)
    print(f"[+] Firmware Trust Score: {score}/100")
    print("  Weak Indicators:", findings["weak"])
    print("  Strong Indicators:", findings["strong"])
