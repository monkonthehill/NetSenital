#!/usr/bin/env python3
"""
scripts/train_model.py

Enterprise-Scale ML Anomaly Detection Training Pipeline for NetSentinel.
Trains Random Forest and XGBoost classifiers on 250,000+ flow records with 5-fold cross-validation,
per-attack family recall breakdown, and feature importance rankings.
Outputs production model artifacts to `models/`.
"""

import json
import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import StratifiedKFold, train_test_split
import xgboost as xgb

FEATURE_COLS = [
    "srcPort", "dstPort", "protocol",
    "duration", "packets", "bytes", "packetsPerSecond", "bytesPerSecond",
    "averagePacketSize", "synCount", "ackCount", "finCount", "rstCount", "pshCount", "urgCount",
    "fwd_packets", "fwd_bytes", "bwd_packets", "bwd_bytes"
]

def load_and_prepare_data(flows_path="Data/flows.csv", labeled_path="Data/labeled_flows.csv"):
    path = labeled_path if os.path.exists(labeled_path) else flows_path
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset {path} not found. Run 'make dataset' first.")

    print(f"[*] Loading flow dataset from {path}...")
    t0 = time.time()
    flows = pd.read_csv(path)
    print(f"[+] Loaded {len(flows):,} flow samples in {time.time() - t0:.2f}s.")

    if "label" not in flows.columns:
        raise ValueError(f"{path} has no 'label' column.")

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

    print("\nClass distribution:")
    for lbl, count in flows["label"].value_counts().items():
        print(f" - {lbl:16s}: {count:7,d} ({count / len(flows) * 100:5.2f}%)")

    # Binary labels: 0 = Benign, 1 = Attack
    y = (flows["label"] != "benign").astype(int)
    X = flows[FEATURE_COLS].copy()

    # Handle any inf/nan gracefully
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    return X, y, flows["label"]

def train_and_evaluate():
    os.makedirs("models", exist_ok=True)
    X, y, raw_labels = load_and_prepare_data()

    # Stratified Train/Test split (75% train, 25% holdout test)
    X_train, X_test, y_train, y_test, labels_train, labels_test = train_test_split(
        X, y, raw_labels, test_size=0.25, random_state=42, stratify=y
    )

    print(f"\n[*] Training set size: {len(X_train):,} | Holdout test set size: {len(X_test):,}")

    # -------------------------------------------------------------------------
    # 5-Fold Stratified Cross-Validation on XGBoost
    # -------------------------------------------------------------------------
    print("\n" + "=" * 65)
    print(" 5-Fold Stratified Cross-Validation (XGBoost)")
    print("=" * 65)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_accs, cv_f1s, cv_aucs = [], [], []

    fold = 1
    for train_idx, val_idx in skf.split(X_train, y_train):
        X_tr, y_tr = X_train.iloc[train_idx], y_train.iloc[train_idx]
        X_va, y_va = X_train.iloc[val_idx], y_train.iloc[val_idx]

        fold_model = xgb.XGBClassifier(
            n_estimators=80,
            max_depth=7,
            learning_rate=0.1,
            tree_method="hist",
            n_jobs=-1,
            random_state=42 + fold,
            eval_metric="logloss"
        )
        fold_model.fit(X_tr, y_tr)
        preds = fold_model.predict(X_va)
        probs = fold_model.predict_proba(X_va)[:, 1]

        acc = accuracy_score(y_va, preds)
        f1 = f1_score(y_va, preds)
        auc = roc_auc_score(y_va, probs)
        cv_accs.append(acc)
        cv_f1s.append(f1)
        cv_aucs.append(auc)

        print(f" Fold {fold}: Accuracy = {acc*100:6.2f}% | F1-Score = {f1*100:6.2f}% | ROC-AUC = {auc:6.4f}")
        fold += 1

    print("-" * 65)
    print(f" CV Mean: Accuracy = {np.mean(cv_accs)*100:6.2f}% (+/- {np.std(cv_accs)*100:4.2f}%)")
    print(f" CV Mean: F1-Score = {np.mean(cv_f1s)*100:6.2f}% (+/- {np.std(cv_f1s)*100:4.2f}%)")
    print(f" CV Mean: ROC-AUC  = {np.mean(cv_aucs):6.4f} (+/- {np.std(cv_aucs):6.4f})")
    print("=" * 65)

    # -------------------------------------------------------------------------
    # 1. Train Random Forest Classifier
    # -------------------------------------------------------------------------
    print("\n--- Training Production Random Forest Classifier (Multi-threaded) ---")
    t_rf = time.time()
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced"
    )
    rf.fit(X_train, y_train)
    rf_elapsed = time.time() - t_rf
    print(f"[+] Random Forest trained in {rf_elapsed:.2f}s.")

    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]

    print("\nRandom Forest Classification Report (Holdout Test Set):")
    print(classification_report(y_test, rf_preds, target_names=["Benign", "Attack"], digits=4))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, rf_preds))
    print(f"ROC-AUC: {roc_auc_score(y_test, rf_probs):.4f}")

    # -------------------------------------------------------------------------
    # 2. Train XGBoost Classifier
    # -------------------------------------------------------------------------
    print("\n--- Training Production XGBoost Classifier (Multi-threaded Histogram) ---")
    t_xgb = time.time()
    xgb_model = xgb.XGBClassifier(
        n_estimators=120,
        max_depth=8,
        learning_rate=0.08,
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
        eval_metric="logloss"
    )
    xgb_model.fit(X_train, y_train)
    xgb_elapsed = time.time() - t_xgb
    print(f"[+] XGBoost trained in {xgb_elapsed:.2f}s.")

    xgb_preds = xgb_model.predict(X_test)
    xgb_probs = xgb_model.predict_proba(X_test)[:, 1]

    print("\nXGBoost Classification Report (Holdout Test Set):")
    print(classification_report(y_test, xgb_preds, target_names=["Benign", "Attack"], digits=4))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, xgb_preds))
    print(f"ROC-AUC: {roc_auc_score(y_test, xgb_probs):.4f}")

    # -------------------------------------------------------------------------
    # Per-Attack Family Detection Breakdown
    # -------------------------------------------------------------------------
    print("\n" + "=" * 65)
    print(" Per-Attack Family Detection Breakdown (Test Set Recall)")
    print("=" * 65)
    test_eval_df = pd.DataFrame({
        "raw_label": labels_test,
        "true_binary": y_test,
        "pred_rf": rf_preds,
        "pred_xgb": xgb_preds,
        "prob_xgb": xgb_probs
    })

    for attack_type in sorted(test_eval_df["raw_label"].unique()):
        subset = test_eval_df[test_eval_df["raw_label"] == attack_type]
        count = len(subset)
        if attack_type == "benign":
            clean_rf = (subset["pred_rf"] == 0).sum()
            clean_xgb = (subset["pred_xgb"] == 0).sum()
            rf_rate = (clean_rf / count) * 100
            xgb_rate = (clean_xgb / count) * 100
            print(f" [BENIGN] {attack_type:14s} ({count:6,d} samples) -> Specificity: RF={rf_rate:5.2f}% | XGB={xgb_rate:5.2f}%")
        else:
            det_rf = (subset["pred_rf"] == 1).sum()
            det_xgb = (subset["pred_xgb"] == 1).sum()
            rf_rate = (det_rf / count) * 100
            xgb_rate = (det_xgb / count) * 100
            avg_threat = subset["prob_xgb"].mean() * 100
            print(f" [ATTACK] {attack_type:14s} ({count:6,d} samples) -> Detection: RF={rf_rate:5.2f}% | XGB={xgb_rate:5.2f}% (Avg Threat: {avg_threat:5.1f}%)")
    print("=" * 65)

    # -------------------------------------------------------------------------
    # Save Model Artifacts & Feature Rankings
    # -------------------------------------------------------------------------
    joblib.dump(rf, "models/rf_model.joblib")
    xgb_model.save_model("models/xgb_model.json")

    feature_importances = {
        name: float(imp)
        for name, imp in zip(FEATURE_COLS, xgb_model.feature_importances_)
    }
    sorted_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))

    metadata = {
        "features": FEATURE_COLS,
        "feature_importances": sorted_importances,
        "training_samples": len(X),
        "test_accuracy": float(accuracy_score(y_test, xgb_preds)),
        "test_f1": float(f1_score(y_test, xgb_preds)),
        "test_roc_auc": float(roc_auc_score(y_test, xgb_probs)),
        "cv_mean_accuracy": float(np.mean(cv_accs)),
        "classes": ["benign", "attack"]
    }

    with open("models/feature_metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)

    print("\n[+] Model artifacts saved successfully:")
    print(" - models/rf_model.joblib")
    print(" - models/xgb_model.json")
    print(" - models/feature_metadata.json")

if __name__ == "__main__":
    train_and_evaluate()
