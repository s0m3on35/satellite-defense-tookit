# utils/train_lstm_model.py
import os
import argparse
import numpy as np
import pandas as pd
from keras.models import Sequential
from keras.layers import LSTM, Dense
from sklearn.preprocessing import MinMaxScaler
from keras.models import save_model

def load_dataset(file_path):
    if file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
        return df.iloc[:, 0].values.astype(float)
    elif file_path.endswith(".json"):
        with open(file_path, 'r') as f:
            data = json.load(f)
        return np.array([d["value"] for d in data])
    else:
        raise ValueError("Unsupported file format.")

def prepare_data(data, look_back):
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data.reshape(-1, 1))
    X, y = [], []
    for i in range(len(data_scaled) - look_back):
        X.append(data_scaled[i:i + look_back])
        y.append(data_scaled[i + look_back])
    return np.array(X), np.array(y), scaler

def build_lstm_model(input_shape):
    model = Sequential()
    model.add(LSTM(50, input_shape=input_shape))
    model.add(Dense(1))
    model.compile(optimizer="adam", loss="mean_squared_error")
    return model

def main(args):
    print("[+] Loading dataset...")
    data = load_dataset(args.input)
    X, y, scaler = prepare_data(data, args.look_back)

    print("[+] Training LSTM model...")
    model = build_lstm_model((args.look_back, 1))
    model.fit(X, y, epochs=args.epochs, batch_size=1, verbose=1)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    save_model(model, args.output)
    print(f"[✓] Model saved to {args.output}")

    if args.scaler_out:
        import joblib
        joblib.dump(scaler, args.scaler_out)
        print(f"[✓] Scaler saved to {args.scaler_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and export LSTM model for telemetry data")
    parser.add_argument("--input", required=True, help="Path to telemetry data (.csv or .json)")
    parser.add_argument("--output", default="models/lstm_model.h5", help="Path to save trained model")
    parser.add_argument("--look_back", type=int, default=10, help="Look-back window size")
    parser.add_argument("--epochs", type=int, default=10, help="Training epochs")
    parser.add_argument("--scaler_out", help="Optional path to save fitted scaler (joblib format)")
    args = parser.parse_args()
    main(args)
