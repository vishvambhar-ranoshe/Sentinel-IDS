# core/ml/train_xgboost.py

import numpy as np
import pickle
import time
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

PROCESSED = "data/processed/"
MODELS    = "data/models/"

def train():
    print("[*] Loading data...")
    X_train = np.load(PROCESSED + "X_train.npy")
    X_test  = np.load(PROCESSED + "X_test.npy")
    y_train = np.load(PROCESSED + "y_train.npy")
    y_test  = np.load(PROCESSED + "y_test.npy")

    # Sample 500k
    idx = np.random.choice(len(X_train), 500000, replace=False)
    X_train = X_train[idx]
    y_train = y_train[idx]

    print("[*] Training XGBoost...")
    start = time.time()

    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        n_jobs=-1,
        random_state=42,
        eval_metric='logloss',
        verbosity=1
    )

    model.fit(X_train, y_train)
    print(f"[*] Done in {round(time.time()-start, 2)}s")

    print("[*] Evaluating...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n--- XGBoost Classification Report ---")
    print(classification_report(y_test, y_pred,
          target_names=["BENIGN", "ATTACK"]))
    print("--- Confusion Matrix ---")
    print(confusion_matrix(y_test, y_pred))
    print(f"--- ROC-AUC: {roc_auc_score(y_test, y_prob):.4f} ---")

    with open(MODELS + "xgboost.pkl", "wb") as f:
        pickle.dump(model, f)
    print("\n[DONE] Saved to data/models/xgboost.pkl")

if __name__ == "__main__":
    train()
