#!/bin/bash
# Path: run_toolkit.sh
# Purpose: Launch Satellite Defense Toolkit (GUI or CLI) 

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

LAUNCHER_GUI="satellite_defense_toolkit_gui.py"
LAUNCHER_CLI="launcher.py"
PYTHON=$(command -v python3 || command -v python || true)
AUDIT_LOG="logs/launch_audit.log"

print_help() {
  echo "Usage: ./run_toolkit.sh [options]"
  echo ""
  echo "Options:"
  echo "  --help         Show this help message"
  echo "  --check        Verify and install required dependencies"
  echo "  --gui          Launch the God-mode graphical interface"
  echo "  --headless     Launch CLI mode (default launcher)"
  echo "  --ws-check     Test WebSocket dashboard connectivity"
  echo ""
}

check_dependencies() {
  echo "[*] Checking Python dependencies..."

  REQUIRED_MODULES=(
    flask flask_socketio websocket-server websockets
    rich termcolor opencv-python pillow numpy
    requests scapy pyyaml pyserial
    blesuite aioblescan openai vosk pyttsx3
    torch transformers torchaudio
  )

  MISSING=()

  for module in "${REQUIRED_MODULES[@]}"; do
    if ! $PYTHON -c "import $module" &>/dev/null; then
      MISSING+=("$module")
    fi
  done

  if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[!] Missing modules: ${MISSING[*]}"
    echo "[*] Installing..."
    $PYTHON -m pip install --upgrade pip
    $PYTHON -m pip install "${MISSING[@]}"
  else
    echo "[+] All dependencies are installed."
  fi
}

check_websocket() {
  echo "[*] Testing WebSocket dashboard..."
  if timeout 3 bash -c "</dev/tcp/localhost/8765" 2>/dev/null; then
    echo "[+] Dashboard WebSocket (localhost:8765) is responsive."
  else
    echo "[!] Dashboard WebSocket not reachable. Is it running?"
  fi
}

log_launch() {
  mkdir -p logs
  echo "$(date +'%Y-%m-%d %H:%M:%S') :: $1" >> "$AUDIT_LOG"
}

# Main logic
case "$1" in
  --help)
    print_help
    exit 0
    ;;
  --check)
    check_dependencies
    exit 0
    ;;
  --ws-check)
    check_websocket
    exit 0
    ;;
  --gui)
    check_dependencies
    if [[ ! -f "$LAUNCHER_GUI" ]]; then
      echo "[ERROR] GUI launcher '$LAUNCHER_GUI' not found."
      exit 1
    fi
    log_launch "GUI launch initiated"
    echo "[+] Launching GUI: $LAUNCHER_GUI"
    exec $PYTHON "$LAUNCHER_GUI"
    ;;
  --headless|*)
    check_dependencies
    if [[ ! -f "$LAUNCHER_CLI" ]]; then
      echo "[ERROR] CLI launcher '$LAUNCHER_CLI' not found."
      exit 1
    fi
    log_launch "CLI launch initiated"
    echo "[+] Launching CLI: $LAUNCHER_CLI"
    exec $PYTHON "$LAUNCHER_CLI"
    ;;
esac
