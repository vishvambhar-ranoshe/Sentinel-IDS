# core/ml/train_isoforest.py

import numpy as np
import pickle
import time
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

PROCESSED = "data/processed/"
MODELS    = "data/models/"

def train():
    print("[*] Loading data...")
    X_normal = np.load(PROCESSED + "X_normal.npy")
    X_test   = np.load(PROCESSED + "X_test.npy")
    y_test   = np.load(PROCESSED + "y_test.npy")

    # Train only on normal traffic like AE
    idx = np.random.choice(len(X_normal), 100000, replace=False)
    X_train = X_normal[idx]

    print(f"[*] Training Isolation Forest on {len(X_train)} normal samples...")
    start = time.time()

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,  # assume 5% anomalies
        n_jobs=-1,
        random_state=42,
        verbose=1
    )

    model.fit(X_train)
    print(f"[*] Done in {round(time.time()-start, 2)}s")

    print("[*] Evaluating...")
    # IsolationForest returns 1=normal, -1=anomaly
    # Convert to 0=benign, 1=attack
    y_pred_raw = model.predict(X_test)
    y_pred = (y_pred_raw == -1).astype(int)

    # Anomaly score — lower = more anomalous
    scores = -model.score_samples(X_test)

    print("\n--- Isolation Forest Report ---")
    print(classification_report(y_test, y_pred,
          target_names=["BENIGN", "ATTACK"]))
    print("--- Confusion Matrix ---")
    print(confusion_matrix(y_test, y_pred))
    print(f"--- ROC-AUC: {roc_auc_score(y_test, scores):.4f} ---")

    with open(MODELS + "isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    print("\n[DONE] Saved to data/models/isolation_forest.pkl")

if __name__ == "__main__":
    train()
