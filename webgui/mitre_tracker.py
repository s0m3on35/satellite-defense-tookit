# webgui/mitre_tracker.py
import json
import os
from datetime import datetime
from flask import Flask, render_template_string

MITRE_TEMPLATE = """
<html>
<head><title>MITRE Tracker</title></head>
<body>
<h2>🔬 MITRE ATT&CK Phase Tracker</h2>
<table border="1">
<tr><th>Tactic</th><th>Technique</th><th>Last Seen</th></tr>
{% for tactic, entries in data.items() %}
  {% for technique, ts in entries.items() %}
    <tr><td>{{ tactic }}</td><td>{{ technique }}</td><td>{{ ts }}</td></tr>
  {% endfor %}
{% endfor %}
</table>
</body>
</html>
"""

LOG_PATH = "results/mitre_map.json"

def parse_logs():
    if not os.path.exists(LOG_PATH):
        return {}
    with open(LOG_PATH, "r") as f:
        return json.load(f)

app = Flask(__name__)

@app.route("/")
def view():
    data = parse_logs()
    return render_template_string(MITRE_TEMPLATE, data=data)

if __name__ == "__main__":
    print("[✓] MITRE Tracker running on http://0.0.0.0:8090")
    app.run(host="0.0.0.0", port=8090)
