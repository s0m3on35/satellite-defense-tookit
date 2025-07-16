#!/usr/bin/env python3
# File: /webgui_web/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json
from pathlib import Path

app = Flask(__name__)
CORS(app)

MODULE_DIR = Path("../modules")
AGENT_FILE = Path("../webgui/agents.json")
LOG_DIR = Path("../logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# === Helper to discover modules ===
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

# === Routes ===

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

    try:
        proc = subprocess.run(
            ["python3", str(abs_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            text=True
        )
        output = proc.stdout.strip()
        return jsonify({"output": output})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/chain", methods=["POST"])
def api_chain():
    data = request.get_json()
    results = []
    for mod in data.get("chain", []):
        module_path = mod.get("file")
        abs_path = MODULE_DIR.parent / module_path
        if abs_path.exists():
            try:
                proc = subprocess.run(
                    ["python3", str(abs_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                    text=True
                )
                results.append({"module": module_path, "output": proc.stdout.strip()})
            except Exception as e:
                results.append({"module": module_path, "error": str(e)})
        else:
            results.append({"module": module_path, "error": "Not found"})
    return jsonify(results)

# === Run the Flask server ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True) lo
