# File: models/train_lstm_model.py

import os
import yaml
import joblib
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from keras.models import Sequential, load_model
from keras.layers import LSTM, Dense
from sklearn.preprocessing import MinMaxScaler

# Constants
CONFIG_PATH = "config/config.yaml"
DATA_PATH = "data/telemetry_data.csv"
MODEL_PATH = "models/lstm_model.h5"
SCALER_PATH = "models/lstm_scaler.pkl"
ALERT_LOG = "logs/anomalies/lstm_alerts.log"

# Ensure required directories
for dir_path in ["models", "logs/anomalies", "config", "data"]:
    os.makedirs(dir_path, exist_ok=True)

# Logging
logging.basicConfig(
    filename=ALERT_LOG,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)

# Default config
DEFAULT_CONFIG = {
    "look_back": 15,
    "threshold": 0.25
}

def create_default_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(DEFAULT_CONFIG, f)
        print(f"[+] Default config.yaml created at {CONFIG_PATH}")

def create_sample_telemetry_csv():
    if not os.path.exists(DATA_PATH):
        timestamps = [datetime.utcnow() + timedelta(seconds=i) for i in range(200)]
        values = np.concatenate([
            np.random.normal(1.0, 0.05, 180),
            np.random.normal(2.0, 0.2, 20)  # Inject 20 anomalies
        ])
        df = pd.DataFrame({
            "timestamp": [t.isoformat() for t in timestamps],
            "value": values
        })
        df.to_csv(DATA_PATH, index=False)
        print(f"[+] Sample telemetry_data.csv created with synthetic data at {DATA_PATH}")

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def load_telemetry_data():
    df = pd.read_csv(DATA_PATH)
    if "value" not in df.columns:
        raise ValueError("CSV must contain a 'value' column.")
    return df["value"].values.astype(np.float32)

def prepare_data(series, look_back):
    scaler = MinMaxScaler()
    series_scaled = scaler.fit_transform(series.reshape(-1, 1))
    X, y = [], []
    for i in range(len(series_scaled) - look_back):
        X.append(series_scaled[i:i + look_back])
        y.append(series_scaled[i + look_back])
    return np.array(X), np.array(y), scaler

def train_model(X, y):
    model = Sequential()
    model.add(LSTM(64, input_shape=(X.shape[1], 1)))
    model.add(Dense(1))
    model.compile(loss='mse', optimizer='adam')
    model.fit(X, y, epochs=30, batch_size=16, verbose=0)
    return model

def detect_anomalies(model, X, y, threshold):
    predictions = model.predict(X, verbose=0)
    errors = np.abs(predictions.flatten() - y.flatten())
    anomalies = np.where(errors > threshold)[0]
    return anomalies, errors

def log_anomalies(anomalies, errors, raw_series, look_back):
    for idx in anomalies:
        value = raw_series[idx + look_back]
        deviation = errors[idx]
        logging.warning(f"Anomaly at idx={idx}, value={value:.4f}, deviation={deviation:.4f}")

def main():
    create_default_config()
    create_sample_telemetry_csv()

    config = load_config()
    look_back = config.get("look_back", 15)
    threshold = config.get("threshold", 0.25)

    series = load_telemetry_data()
    X, y, scaler = prepare_data(series, look_back)

    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        print("[*] Training new LSTM model...")
        model = train_model(X, y)
        model.save(MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        print(f"[✓] Model saved to {MODEL_PATH}")
        print(f"[✓] Scaler saved to {SCALER_PATH}")
    else:
        print("[*] Loading existing model...")
        model = load_model(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)

    anomalies, errors = detect_anomalies(model, X, y, threshold)
    if len(anomalies):
        log_anomalies(anomalies, errors, series, look_back)
        print(f"[!] {len(anomalies)} anomalies detected and logged to {ALERT_LOG}")
    else:
        print("[✓] No anomalies detected.")

if __name__ == "__main__":
    main()
