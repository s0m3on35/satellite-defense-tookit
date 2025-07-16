# File: models/train_lstm_model.py

import os
import yaml
import joblib
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from keras.models import Sequential
from keras.layers import LSTM, Dense
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error

# Setup
CONFIG_PATH = "config/config.yaml"
DATA_PATH = "data/telemetry_data.csv"
MODEL_PATH = "models/lstm_model.h5"
SCALER_PATH = "models/lstm_scaler.pkl"
ALERT_LOG = "logs/anomalies/lstm_alerts.log"
os.makedirs("logs/anomalies", exist_ok=True)

logging.basicConfig(filename=ALERT_LOG, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError("Configuration file not found.")
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def load_telemetry_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Telemetry data not found: {path}")
    df = pd.read_csv(path)
    if "value" not in df.columns:
        raise ValueError("CSV must contain a 'value' column.")
    return df["value"].values.astype(np.float32)

def prepare_data(series, look_back):
    scaler = MinMaxScaler()
    series_scaled = scaler.fit_transform(series.reshape(-1, 1))
    X, y = [], []
    for i in range(len(series_scaled) - look_back):
        X.append(series_scaled[i:i+look_back])
        y.append(series_scaled[i+look_back])
    return np.array(X), np.array(y), scaler

def train_model(X, y):
    model = Sequential()
    model.add(LSTM(64, input_shape=(X.shape[1], 1)))
    model.add(Dense(1))
    model.compile(loss='mse', optimizer='adam')
    model.fit(X, y, epochs=25, batch_size=16, verbose=0)
    return model

def detect_anomalies(model, X, y, threshold):
    predictions = model.predict(X, verbose=0)
    errors = np.abs(predictions.flatten() - y.flatten())
    anomalies = np.where(errors > threshold)[0]
    return anomalies, errors

def log_anomalies(anomalies, errors, raw_series, look_back):
    for idx in anomalies:
        timestamp = datetime.utcnow().isoformat()
        original_value = raw_series[idx + look_back]
        deviation = errors[idx]
        logging.warning(f"Anomaly detected at index={idx}, value={original_value:.3f}, deviation={deviation:.3f}")

def main():
    config = load_config()
    look_back = config.get("look_back", 10)
    threshold = config.get("threshold", 0.15)

    series = load_telemetry_data(DATA_PATH)
    X, y, scaler = prepare_data(series, look_back)

    if not os.path.exists(MODEL_PATH):
        print("[*] Training new LSTM model...")
        model = train_model(X, y)
        model.save(MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        print("[✓] Model and scaler saved.")
    else:
        print("[*] Loading existing model...")
        model = load_model(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)

    anomalies, errors = detect_anomalies(model, X, y, threshold)
    if len(anomalies) > 0:
        log_anomalies(anomalies, errors, series, look_back)
        print(f"[!] {len(anomalies)} anomalies detected and logged.")
    else:
        print("[✓] No anomalies detected.")

if __name__ == "__main__":
    main()
