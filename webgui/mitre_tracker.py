#!/usr/bin/env python3
# Route: webgui/mitre_tracker.py

import json
import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify

LOG_PATH = "results/mitre_map.json"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MITRE ATT&CK Tracker</title>
  <style>
    body {
      font-family: "Fira Code", monospace;
      background-color: #0f0f0f;
      color: #f0f0f0;
      padding: 30px;
    }
    h2 {
      text-align: center;
      color: #3cb371;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    th, td {
      border: 1px solid #444;
      padding: 8px;
      text-align: left;
    }
    th {
      background-color: #222;
      color: #ccc;
    }
    tr:nth-child(even) {
      background-color: #1c1c1c;
    }
    tr:hover {
      background-color: #333;
    }
    .toolbar {
      text-align: right;
      margin-top: 10px;
    }
    button {
      padding: 6px 12px;
      background-color: #444;
      color: #ccc;
      border: 1px solid #666;
      cursor: pointer;
    }
    button:hover {
      background-color: #666;
    }
  </style>
</head>
<body>
  <h2>MITRE ATT&CK Phase Tracker</h2>
  <div class="toolbar">
    <button onclick="window.location.reload()">Refresh</button>
    <button onclick="exportTable('csv')">Export CSV</button>
    <button onclick="exportTable('md')">Export Markdown</button>
  </div>
  <table id="mitre-table">
    <tr>
      <th>Tactic</th>
      <th>Technique</th>
      <th>Last Seen</th>
    </tr>
    {% for tactic, entries in data.items() %}
      {% for technique, ts in entries|dictsort(by='value', reverse=True) %}
        <tr>
          <td>{{ tactic }}</td>
          <td>{{ technique }}</td>
          <td title="{{ ts }}">{{ ts|datetimeformat }}</td>
        </tr>
      {% endfor %}
    {% endfor %}
  </table>
  <script>
    function exportTable(format) {
      fetch('/export?format=' + format)
        .then(response => response.text())
        .then(data => {
          const blob = new Blob([data], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'mitre_tracker_export.' + format;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
        });
    }
  </script>
</body>
</html>"""

app = Flask(__name__)

@app.template_filter("datetimeformat")
def datetimeformat(value):
    try:
        return datetime.utcfromtimestamp(float(value)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return value

def parse_logs():
    if not os.path.exists(LOG_PATH):
        return {}
    try:
        with open(LOG_PATH, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

@app.route("/")
def view():
    data = parse_logs()
    return render_template_string(HTML_TEMPLATE, data=data)

@app.route("/export")
def export():
    fmt = request.args.get("format", "csv")
    data = parse_logs()
    output = ""
    if fmt == "csv":
        output = "Tactic,Technique,Last Seen\n"
        for tactic, techniques in data.items():
            for tech, ts in techniques.items():
                ts_fmt = datetimeformat(ts)
                output += f"{tactic},{tech},{ts_fmt}\n"
    elif fmt == "md":
        output = "| Tactic | Technique | Last Seen |\n|--------|-----------|------------|\n"
        for tactic, techniques in data.items():
            for tech, ts in techniques.items():
                ts_fmt = datetimeformat(ts)
                output += f"| {tactic} | {tech} | {ts_fmt} |\n"
    return output

if __name__ == "__main__":
    print("[â] MITRE Tracker running on http://0.0.0.0:8090")
    app.run(host="0.0.0.0", port=8090)
