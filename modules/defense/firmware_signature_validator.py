#!/usr/bin/env python3
# Route: modules/defense/firmware_signature_validator.py
# Description: Validates integrity and authenticity of firmware using digital signatures (RSA/
import os
import hashlib
import subprocess
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature

FIRMWARE_IMAGE = "/firmware/ota_image.bin"
SIGNATURE_FILE = "/firmware/ota_image.sig"
PUBLIC_KEY_FILE = "/etc/sdt_firmware_pubkey.pem"
ALERT_LOG = "/var/log/sdt_firmware_validation.log"

def log_alert(message):
    from datetime import datetime
    timestamp = datetime.utcnow().isoformat()
    entry = f"{timestamp} - {message}"
    with open(ALERT_LOG, 'a') as f:
        f.write(entry + '\n')
    subprocess.call(['logger', '-p', 'auth.crit', entry])

def load_public_key():
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        key_data = f.read()
        if b"BEGIN PUBLIC KEY" in key_data:
            return serialization.load_pem_public_key(key_data)
        raise Exception("Invalid public key format.")

def validate_firmware():
    if not all(os.path.exists(f) for f in [FIRMWARE_IMAGE, SIGNATURE_FILE, PUBLIC_KEY_FILE]):
        log_alert("Missing firmware, signature, or public key file.")
        return False

    with open(FIRMWARE_IMAGE, 'rb') as f:
        firmware_data = f.read()
    with open(SIGNATURE_FILE, 'rb') as f:
        signature = f.read()

    try:
        public_key = load_public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                firmware_data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            public_key.verify(
                signature,
                firmware_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        print("[*] Firmware signature valid.")
        return True
    except InvalidSignature:
        log_alert("Firmware signature INVALID – possible tampering.")
        return False
    except Exception as e:
        log_alert(f"Error during firmware validation: {str(e)}")
        return False

if __name__ == "__main__":
    print("[*] Running firmware authenticity check...")
    if not validate_firmware():
        print("[!] Firmware failed validation. Alert triggered.")
    else:
        print("[+] Firmware validated successfully.")
