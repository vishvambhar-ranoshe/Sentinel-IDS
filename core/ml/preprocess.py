# core/ml/preprocess.py

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
import os

RAW_PATH = "data/raw/"
PROCESSED_PATH = "data/processed/"

FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'SYN Flag Count',
    'ACK Flag Count',
    'RST Flag Count',
    'FIN Flag Count',
    'PSH Flag Count',
    'Destination Port',
    'Protocol',
    'Label'
]

def load_all_csvs():
    print("[*] Loading CSVs...")
    dfs = []
    for f in os.listdir(RAW_PATH):
        if f.endswith(".csv"):
            print(f"    Loading {f}")
            df = pd.read_csv(RAW_PATH + f, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
    combined = pd.concat(dfs, ignore_index=True)
    print(f"[*] Total rows loaded: {len(combined)}")
    return combined

def clean(df):
    print("[*] Cleaning...")

    # Keep only our features
    df = df[[c for c in FEATURES if c in df.columns]]

    # Drop nulls and infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Strip label whitespace
    df['Label'] = df['Label'].str.strip()

    print(f"[*] Rows after cleaning: {len(df)}")
    print(f"[*] Label distribution:\n{df['Label'].value_counts()}")
    return df

def encode_and_scale(df):
    print("[*] Encoding and scaling...")

    X = df.drop('Label', axis=1)
    y = df['Label']

    # Binary label — BENIGN = 0, everything else = 1
    y_binary = (y != 'BENIGN').astype(int)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Save scaler for use during live detection
    with open(PROCESSED_PATH + "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    print("[*] Scaler saved")
    return X_scaled, y_binary.values, y.values, X.columns.tolist()

def split_and_save(X, y_binary, y_labels):
    print("[*] Splitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
    )

    # Normal only — for Autoencoder training
    X_normal = X_train[y_train == 0]

    np.save(PROCESSED_PATH + "X_train.npy", X_train)
    np.save(PROCESSED_PATH + "X_test.npy", X_test)
    np.save(PROCESSED_PATH + "y_train.npy", y_train)
    np.save(PROCESSED_PATH + "y_test.npy", y_test)
    np.save(PROCESSED_PATH + "X_normal.npy", X_normal)

    print(f"[*] Train size: {len(X_train)}")
    print(f"[*] Test size:  {len(X_test)}")
    print(f"[*] Normal only (for Autoencoder): {len(X_normal)}")
    print("[*] All splits saved to data/processed/")

if __name__ == "__main__":
    os.makedirs(PROCESSED_PATH, exist_ok=True)
    df = load_all_csvs()
    df = clean(df)
    X, y_binary, y_labels, feature_names = encode_and_scale(df)
    split_and_save(X, y_binary, y_labels)
    print("[DONE] Preprocessing complete")
