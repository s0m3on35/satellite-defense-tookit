##!/usr/bin/env python3
# File: /webgui_web/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import subprocess
import os
import json
from pathlib import Path
from threading import Thread

app = Flask(__name__)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

MODULE_DIR = Path("../modules")
AGENT_FILE = Path("../webgui/agents.json")
LOG_DIR = Path("../logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# === Discover modules ===
def discover_modules():
    modules = []
    for root, _, files in os.walk(MODULE_DIR):
        for f in files:
            if f.endswith(".py") and not f.startswith("__"):
                path = Path(root) / f
                category = Path(root).name
                modules.append({
                    "name": f.replace(".py", "").replace("_", " ").title(),
                    "file": str(path.relative_to(MODULE_DIR.parent)),
                    "category": category.title()
                })
    return modules

# === API Endpoints ===
@app.route("/api/modules", methods=["GET"])
def api_modules():
    return jsonify(discover_modules())

@app.route("/api/agents", methods=["GET"])
def api_agents():
    if AGENT_FILE.exists():
        with open(AGENT_FILE) as f:
            return jsonify(json.load(f))
    return jsonify([])

@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json()
    module_path = data.get("file")
    if not module_path:
        return jsonify({"error": "No module specified"}), 400

    abs_path = MODULE_DIR.parent / module_path
    if not abs_path.exists():
        return jsonify({"error": "Module not found"}), 404

    def stream_output():
        try:
            proc = subprocess.Popen(
                ["python3", str(abs_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in proc.stdout:
                socketio.emit("console_output", {"line": line.strip()})
            proc.wait()
            socketio.emit("console_output", {"line": f"[{module_path}] execution completed."})
        except Exception as e:
            socketio.emit("console_output", {"line": f"[ERROR] {str(e)}"})

    Thread(target=stream_output).start()
    return jsonify({"status": "started"})

@app.route("/api/chain", methods=["POST"])
def api_chain():
    data = request.get_json()
    sequence = data.get("chain", [])

    def run_chain():
        for mod in sequence:
            module_path = mod.get("file")
            abs_path = MODULE_DIR.parent / module_path
            if abs_path.exists():
                socketio.emit("console_output", {"line": f"[*] Running {module_path}"})
                try:
                    proc = subprocess.Popen(
                        ["python3", str(abs_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    for line in proc.stdout:
                        socketio.emit("console_output", {"line": line.strip()})
                    proc.wait()
                except Exception as e:
                    socketio.emit("console_output", {"line": f"[ERROR] {module_path}: {str(e)}"})
            else:
                socketio.emit("console_output", {"line": f"[ERROR] Module not found: {module_path}"})
        socketio.emit("console_output", {"line": "[*] Chain execution complete."})

    Thread(target=run_chain).start()
    return jsonify({"status": "chain_started"})

# === WebSocket Events ===
@socketio.on("connect")
def handle_connect():
    emit("console_output", {"line": "[WebSocket] Connected to server."})

# === Start Server ===
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
