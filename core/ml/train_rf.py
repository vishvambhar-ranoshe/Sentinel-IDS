# core/ml/train_rf.py

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import pickle
import time

PROCESSED = "data/processed/"
MODELS = "data/models/"

def train():
    print("[*] Loading data...")
    X_train = np.load(PROCESSED + "X_train.npy")
    X_test  = np.load(PROCESSED + "X_test.npy")
    y_train = np.load(PROCESSED + "y_train.npy")
    y_test  = np.load(PROCESSED + "y_test.npy")

    print(f"[*] Train: {X_train.shape}, Test: {X_test.shape}")

    # Sample to speed up training — 500k is enough for strong model
    print("[*] Sampling 500k rows for training...")
    idx = np.random.choice(len(X_train), 500000, replace=False)
    X_train = X_train[idx]
    y_train = y_train[idx]

    print("[*] Training Random Forest...")
    start = time.time()

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=10,
        n_jobs=-1,          # use all CPU cores
        random_state=42,
        verbose=1
    )

    model.fit(X_train, y_train)
    duration = round(time.time() - start, 2)
    print(f"[*] Training done in {duration}s")

    print("[*] Evaluating...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred,
          target_names=["BENIGN", "ATTACK"]))

    print("--- Confusion Matrix ---")
    print(confusion_matrix(y_test, y_pred))

    print(f"--- ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f} ---")

    # Save model
    with open(MODELS + "random_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    print("\n[DONE] Model saved to data/models/random_forest.pkl")

if __name__ == "__main__":
    train()
