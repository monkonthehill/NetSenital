#!/usr/bin/env python3
"""
scripts/train_model.py

Trains Random Forest and XGBoost network anomaly detection models on NetSentinel flow features.
Outputs trained model artifacts, metrics, and feature importances to `models/`.
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
import xgboost as xgb

FEATURE_COLS = [
    "srcPort", "dstPort", "protocol",
    "duration", "packets", "bytes", "packetsPerSecond", "bytesPerSecond",
    "averagePacketSize", "synCount", "ackCount", "finCount", "rstCount", "pshCount", "urgCount",
    "fwd_packets", "fwd_bytes", "bwd_packets", "bwd_bytes"
]

def load_and_prepare_data(flows_path="Data/flows.csv", windows_path="Data/attack_windows.csv"):
    if not os.path.exists(flows_path):
        raise FileNotFoundError(f"Dataset {flows_path} not found.")

    flows = pd.read_csv(flows_path)
    
    # Check if 'label' already exists; if not, auto-label using attack windows if available
    if "label" not in flows.columns:
        if os.path.exists(windows_path):
            windows = pd.read_csv(windows_path)
            flows["label"] = "benign"
            for _, w in windows.iterrows():
                in_window = flows["startTimeUnixMs"].between(w["start_ts"], w["end_ts"])
                involves_attacker = (flows["srcIp"] == w["attacker_ip"]) | (flows["dstIp"] == w["attacker_ip"])
                flows.loc[in_window & involves_attacker, "label"] = w["attack_type"]
        else:
            raise ValueError(f"flows.csv has no 'label' column and {windows_path} is missing.")

    # Fill directional counters with reasonable estimates if legacy dataset without directional columns
    for col in ["fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes"]:
        if col not in flows.columns:
            if col == "fwd_packets":
                flows[col] = flows["packets"]
            elif col == "bwd_packets":
                flows[col] = 0
            elif col == "fwd_bytes":
                flows[col] = flows["bytes"]
            elif col == "bwd_bytes":
                flows[col] = 0

    print(f"Loaded {len(flows)} total flow samples.")
    print("Class distribution:")
    print(flows["label"].value_counts())

    # Map labels: binary classification (0 = benign, 1 = attack)
    y = (flows["label"] != "benign").astype(int)
    X = flows[FEATURE_COLS].copy()

    # Handle any inf/nan gracefully
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    return X, y, flows["label"]

def train_and_evaluate():
    os.makedirs("models", exist_ok=True)
    X, y, raw_labels = load_and_prepare_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"\nTraining set size: {len(X_train)} | Test set size: {len(X_test)}")

    # 1. Train Random Forest Classifier
    print("\n--- Training Random Forest Classifier ---")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, class_weight="balanced")
    rf.fit(X_train, y_train)

    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]

    print("\nRandom Forest Classification Report:")
    print(classification_report(y_test, rf_preds, target_names=["Benign", "Attack"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, rf_preds))
    print(f"ROC-AUC: {roc_auc_score(y_test, rf_probs):.4f}")

    # 2. Train XGBoost Classifier
    print("\n--- Training XGBoost Classifier ---")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric="logloss"
    )
    xgb_model.fit(X_train, y_train)

    xgb_preds = xgb_model.predict(X_test)
    xgb_probs = xgb_model.predict_proba(X_test)[:, 1]

    print("\nXGBoost Classification Report:")
    print(classification_report(y_test, xgb_preds, target_names=["Benign", "Attack"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, xgb_probs):.4f}")

    # Save models
    rf_path = "models/rf_model.joblib"
    xgb_path = "models/xgb_model.json"
    features_path = "models/feature_metadata.json"

    joblib.dump(rf, rf_path)
    xgb_model.save_model(xgb_path)

    metadata = {
        "features": FEATURE_COLS,
        "n_features": len(FEATURE_COLS),
        "target": "is_attack",
        "rf_test_auc": float(roc_auc_score(y_test, rf_probs)),
        "xgb_test_auc": float(roc_auc_score(y_test, xgb_probs))
    }
    with open(features_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nSaved models:")
    print(f" - {rf_path}")
    print(f" - {xgb_path}")
    print(f" - {features_path}")

if __name__ == "__main__":
    train_and_evaluate()
