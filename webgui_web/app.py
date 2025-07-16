#!/usr/bin/env python3
# File: /webgui_web/app.py

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import subprocess
import os
import json
from pathlib import Path
from threading import Thread
import time

app = Flask(__name__)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

MODULES_DIR = Path("../modules")
AGENTS_FILE = Path("../webgui/agents.json")
AUDIT_LOG = Path("../logs/audit_trail.jsonl")
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

# === Module Discovery ===
def discover_modules():
    modules = []
    for root, _, files in os.walk(MODULES_DIR):
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                full_path = Path(root) / file
                rel_path = full_path.relative_to(MODULES_DIR.parent)
                category = full_path.parent.name
                modules.append({
                    "name": file.replace(".py", "").replace("_", " ").title(),
                    "file": str(rel_path),
                    "category": category.title()
                })
    return modules

# === WebSocket Connect ===
@socketio.on("connect")
def on_connect():
    emit("console_output", {"line": "[WebSocket] Connected to server."})

# === Stream Output to WebSocket ===
def stream_process_output(proc, module_path, agent_id=None):
    for line in proc.stdout:
        line = line.strip()
        socketio.emit("console_output", {"line": line})
    proc.wait()
    socketio.emit("console_output", {"line": f"[{module_path}] execution completed."})
    if agent_id:
        log_audit_entry(module_path, agent_id)

def log_audit_entry(module, agent):
    entry = {
        "timestamp": int(time.time()),
        "module": module,
        "agent": agent
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

# === Routes ===
@app.route("/api/modules", methods=["GET"])
def get_modules():
    return jsonify(discover_modules())

@app.route("/api/agents", methods=["GET"])
def get_agents():
    if AGENTS_FILE.exists():
        with open(AGENTS_FILE) as f:
            return jsonify(json.load(f))
    return jsonify([])

@app.route("/api/run", methods=["POST"])
def run_single_module():
    data = request.get_json()
    module_path = data.get("file")
    agent_id = data.get("agent", "unknown")

    if not module_path:
        return jsonify({"error": "Module path not specified"}), 400

    abs_path = MODULES_DIR.parent / module_path
    if not abs_path.exists():
        return jsonify({"error": "Module not found"}), 404

    def run():
        try:
            proc = subprocess.Popen(
                ["python3", str(abs_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            stream_process_output(proc, module_path, agent_id)
        except Exception as e:
            socketio.emit("console_output", {"line": f"[ERROR] {str(e)}"})

    Thread(target=run).start()
    return jsonify({"status": "started"})

@app.route("/api/chain", methods=["POST"])
def run_execution_chain():
    data = request.get_json()
    chain = data.get("chain", [])
    agent_id = data.get("agent", "unknown")

    def run_chain():
        for mod in chain:
            path = mod.get("file")
            abs_path = MODULES_DIR.parent / path
            socketio.emit("console_output", {"line": f"[*] Running {path}"})
            if abs_path.exists():
                try:
                    proc = subprocess.Popen(
                        ["python3", str(abs_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    stream_process_output(proc, path, agent_id)
                except Exception as e:
                    socketio.emit("console_output", {"line": f"[ERROR] {str(e)}"})
            else:
                socketio.emit("console_output", {"line": f"[ERROR] File not found: {path}"})
        socketio.emit("console_output", {"line": "[*] Chain execution complete."})

    Thread(target=run_chain).start()
    return jsonify({"status": "chain_started"})

# === Serve Logs ===
@app.route("/logs/<path:filename>", methods=["GET"])
def get_log(filename):
    log_dir = AUDIT_LOG.parent.resolve()
    return send_from_directory(str(log_dir), filename)

# === Launch ===
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
