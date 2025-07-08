#!/bin/bash
# Path: run_toolkit.sh

set -e

# Ensure script is run from toolkit root
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

LAUNCHER="launcher.py"
PYTHON=$(command -v python3 || true)

print_help() {
  echo "Usage: ./run_toolkit.sh [options]"
  echo "Options:"
  echo "  --help        Show this help message"
  echo "  --check       Check and install required dependencies"
  echo "  --gui         Launch with graphical interface"
  echo "  --headless    Launch in headless CLI mode"
  echo ""
}

check_dependencies() {
  echo "[*] Verifying required Python modules..."

  REQUIRED_MODULES=(flask flask_socketio websocket-server websockets rich termcolor opencv-python pillow numpy requests scapy pyyaml pyserial blesuite aioblescan openai vosk pyttsx3 torch transformers torchaudio)
  
  for module in "${REQUIRED_MODULES[@]}"; do
    if ! $PYTHON -c "import $module" &>/dev/null; then
      echo "[!] Missing Python module: $module"
      MISSING=1
    fi
  done

  if [[ $MISSING -eq 1 ]]; then
    echo "[*] Installing missing dependencies..."
    $PYTHON -m pip install --upgrade pip
    $PYTHON -m pip install "${REQUIRED_MODULES[@]}"
  else
    echo "[+] All dependencies are satisfied."
  fi
}

# Handle args
if [[ "$1" == "--help" ]]; then
  print_help
  exit 0
elif [[ "$1" == "--check" ]]; then
  check_dependencies
  exit 0
fi

# Check if launcher exists
if [[ ! -f "$LAUNCHER" ]]; then
  echo "[ERROR] Launcher file '$LAUNCHER' not found in $BASE_DIR"
  exit 1
fi

# Optionally check dependencies on first run
check_dependencies

echo "[+] Launching Satellite Defense Toolkit..."
exec $PYTHON "$LAUNCHER" "$@"
