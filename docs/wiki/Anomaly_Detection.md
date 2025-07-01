## Anomaly Detection

This module applies machine learning and statistical methods to identify anomalies in satellite data streams. It includes support for both GNSS and telemetry-based inputs.

---

## GNSS Anomaly Detection

**Method:** Isolation Forest  
**Key Features:**
- Configurable contamination parameter to adjust sensitivity
- Detects anomalies in GNSS data such as:
  - Time drift
  - Sudden location jumps

---

## Telemetry Anomaly Detection

**Method:** Z-score over rolling mean  
**Key Features:**
- Detects anomalies in health telemetry streams (e.g., voltage, temperature)
- Real-time plotting of deviation spikes when thresholds are exceeded

---

## Integration and Output

- Compatible with `config/config.yaml` for custom thresholds
- Outputs structured logs to `logs/anomalies/`
- Can trigger alert modules or auto-chain to mitigation scripts
