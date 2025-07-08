#!/usr/bin/env python3
# Route: modules/defense/secure_update_guard.py
# Description: Verifies OTA update authenticity, integrity, and origin before allowing deployment

import os
import subprocess
import json
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature

UPDATE_META = "/firmware/update_manifest.json"
FIRMWARE_IMAGE = "/firmware/update_payload.bin"
SIGNATURE_FILE = "/firmware/update_payload.sig"
PUBLIC_KEY_FILE = "/etc/sdt_ota_pubkey.pem"
ALERT_LOG = "/var/log/sdt_update_guard.log"

def log_alert(msg):
    from datetime import datetime
    entry = f"{datetime.utcnow().isoformat()} - {msg}"
    with open(ALERT_LOG, 'a') as f:
        f.write(entry + '\n')
    subprocess.call(['logger', '-p', 'auth.crit', entry])

def load_manifest():
    if not os.path.exists(UPDATE_META):
        raise FileNotFoundError("Missing update manifest.")
    with open(UPDATE_META, 'r') as f:
        return json.load(f)

def load_public_key():
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def validate_signature(firmware_data, signature):
    pubkey = load_public_key()
    try:
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(signature, firmware_data, ec.ECDSA(hashes.SHA256()))
        else:
            pubkey.verify(signature, firmware_data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

def validate_firmware_hash(firmware_data, expected_hash):
    h = hashlib.sha256(firmware_data).hexdigest()
    return h == expected_hash

def enforce_source_trust(manifest):
    allowed_sources = ["update.sdt.mil", "groundstation.defense.local"]
    return manifest.get("source") in allowed_sources

def validate_update():
    if not all(os.path.exists(f) for f in [FIRMWARE_IMAGE, SIGNATURE_FILE, UPDATE_META, PUBLIC_KEY_FILE]):
        log_alert("Missing update component.")
        return False

    with open(FIRMWARE_IMAGE, 'rb') as f:
        firmware = f.read()
    with open(SIGNATURE_FILE, 'rb') as f:
        signature = f.read()

    manifest = load_manifest()
    if not enforce_source_trust(manifest):
        log_alert("Update source not trusted.")
        return False

    if not validate_firmware_hash(firmware, manifest.get("sha256", "")):
        log_alert("Firmware hash mismatch – integrity failure.")
        return False

    if not validate_signature(firmware, signature):
        log_alert("Signature invalid – authenticity failure.")
        return False

    return True

def deploy_firmware():
    print("[*] Deployment authorized. Proceeding with firmware install...")
    subprocess.call(["/usr/bin/firmware_installer", FIRMWARE_IMAGE])

def main():
    print("[*] Validating secure OTA update...")
    if validate_update():
        deploy_firmware()
    else:
        print("[!] Update rejected. Alerts logged.")

if __name__ == "__main__":
    main()
