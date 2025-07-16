
# Anomaly Detection

This module provides machine learning and statistical detection capabilities to identify abnormal patterns in satellite communications and subsystem telemetry. It is designed for real-time or batch processing and integrates with Copilot, logging, dashboard alerting, and automatic post-execution chaining.

---

## GNSS Anomaly Detection

**Detection Method:** Isolation Forest (unsupervised anomaly detection)

**Key Capabilities:**
- Supports GNSS input streams (NMEA, binary, or custom JSON)
- Identifies spatial-temporal inconsistencies such as:
  - Time drift or rollback
  - Unrealistic speed or movement jumps
  - Orbit or altitude deviations

**Advanced Configuration:**
- Adjustable `contamination` parameter to tune sensitivity
- Preprocessing for velocity, time delta, satellite count, and Doppler shift

**Sample Output:**
```json
{
  "timestamp": "2025-07-16T14:01:20Z",
  "gps_coords": [42.2331, -8.7124],
  "anomaly_score": 0.94,
  "type": "GNSS Drift",
  "severity": "high"
}
```

---

## Telemetry Anomaly Detection

**Detection Method:** Z-score over rolling statistical mean

**Targets:**
- Subsystem telemetry such as:
  - Voltage regulators
  - Battery capacity
  - Internal bus temperature
  - Reaction wheel RPM or torque

**Detection Features:**
- Uses rolling mean and standard deviation
- Plots real-time deviation spikes above configurable threshold
- Detects gradual drift and sudden spikes

**Visualization:**
- Matplotlib plots triggered if GUI or dashboard is active
- JSONL export for dashboard replay and audit

---

## Integration and Output

| Feature | Description |
|--------|-------------|
| Configurable thresholds | Reads from `config/config.yaml` (Z-score limit, Isolation Forest settings) |
| Logs | Outputs to `logs/anomalies/{gnss,telemetry}_anomalies.jsonl` |
| Post-action chaining | Can trigger defense modules or AI Copilot suggestions |
