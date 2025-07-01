# Configuration Guide

This guide explains how modules in the Satellite Defense Toolkit read parameters from a unified configuration file.

---

## 1. Configuration File Location

All modules use a shared YAML configuration file located at:

```
config/config.yaml
```

This file centralizes runtime options, making the toolkit easily customizable and automatable.

---

## 2. Sample Configuration Format

```yaml
scan_range: [1570, 1620]        # GNSS or RF frequency range (MHz)
duration: 10                    # Duration of each scan or polling cycle (seconds)
threshold: 3.0                  # Anomaly detection sensitivity or entropy threshold
firmware_path: sample_firmware.bin
expected_hash: 123456abcdef7890...
agent_id: sat-telemetry-001
alert_webhook: http://127.0.0.1:8080/alert
```

---

## 3. Common Keys and Their Usage

| Key             | Description                                                     |
|------------------|-----------------------------------------------------------------|
| `scan_range`     | Frequency range in MHz for RF/GNSS scanning modules            |
| `duration`       | Time window in seconds for active monitoring or polling        |
| `threshold`      | Sensitivity value for anomaly detection models                 |
| `firmware_path`  | Absolute or relative path to the monitored firmware binary     |
| `expected_hash`  | Precomputed SHA256 or MD5 hash used for integrity validation   |
| `agent_id`       | Identifier for the agent or endpoint reporting to the dashboard|
| `alert_webhook`  | URL to post alerts or telemetry anomalies                      |

---

## 4. Best Practices

- Use consistent `agent_id` naming for better inventory tracking
- Update `expected_hash` after firmware upgrades
- Avoid hardcoded credentials or secrets in YAML files; use `.env` or vaults instead
- Backup your `config.yaml` during deployments or updates

---

## 5. Notes

- YAML must be correctly indented using spaces, not tabs
- The configuration file supports extension for custom modules and new parameters
