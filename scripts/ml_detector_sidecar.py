#!/usr/bin/env python3
"""
scripts/ml_detector_sidecar.py

Real-Time NetSentinel ML Anomaly Detection Sidecar.
Subscribes to live flow feature streams over ZeroMQ or reads live flow logs,
performs instant inference using the trained XGBoost / Random Forest models,
and outputs security alerts with anomaly probability scores.
"""

import argparse
import json
import os
import sys
import time
import numpy as np
import pandas as pd
import joblib
import xgboost as xgb

try:
    import zmq
    HAS_ZMQ = True
except ImportError:
    HAS_ZMQ = False

FEATURE_COLS = [
    "srcPort", "dstPort", "protocol",
    "duration", "packets", "bytes", "packetsPerSecond", "bytesPerSecond",
    "averagePacketSize", "synCount", "ackCount", "finCount", "rstCount", "pshCount", "urgCount",
    "fwd_packets", "fwd_bytes", "bwd_packets", "bwd_bytes"
]

class AnomalyDetector:
    def __init__(self, model_type="xgb", threshold=0.6):
        self.model_type = model_type
        self.threshold = threshold
        self.category_model = None
        self.attack_classes = {
            0: "Benign",
            1: "SYN Flood",
            2: "Port Scan",
            3: "Stealth Scan",
            4: "UDP Flood",
            5: "Slowloris",
            6: "Slow POST",
            7: "Brute Force",
            8: "ICMP Flood",
        }

        if os.path.exists("models/attack_classes.json"):
            try:
                with open("models/attack_classes.json") as f:
                    raw_classes = json.load(f)
                    self.attack_classes = {int(k): str(v) for k, v in raw_classes.items()}
            except Exception:
                pass

        cat_path = "models/category_model.json"
        if os.path.exists(cat_path):
            try:
                self.category_model = xgb.XGBClassifier()
                self.category_model.load_model(cat_path)
            except Exception as e:
                print(f"[Detector] Warning loading category model: {e}")

        if model_type == "xgb":
            model_path = "models/xgb_model.json"
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"XGBoost model not found at {model_path}. Run scripts/train_model.py first.")
            self.model = xgb.XGBClassifier()
            self.model.load_model(model_path)
        elif model_type == "rf":
            model_path = "models/rf_model.joblib"
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Random Forest model not found at {model_path}. Run scripts/train_model.py first.")
            self.model = joblib.load(model_path)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

        print(f"[Detector] Loaded {model_type.upper()} model with anomaly threshold {self.threshold:.2f}")

    def predict(self, feature_dict):
        # Extract features vector matching training schema
        row = [float(feature_dict.get(c, 0.0)) for c in FEATURE_COLS]
        X = pd.DataFrame([row], columns=FEATURE_COLS)

        if self.model_type == "xgb":
            prob = float(self.model.predict_proba(X)[0][1])
        else:
            prob = float(self.model.predict_proba(X)[0][1])

        is_anomaly = prob >= self.threshold
        attack_type = "Benign"

        if is_anomaly:
            if self.category_model is not None:
                cat_probs = self.category_model.predict_proba(X)[0]
                cid = int(np.argmax(cat_probs))
                if cid == 0:
                    cid = int(np.argmax(cat_probs[1:])) + 1
                attack_type = self.attack_classes.get(cid, "Attack")
            else:
                attack_type = "Attack"

        return is_anomaly, prob, attack_type

def run_zmq_listener(detector, endpoint="ipc:///tmp/netsentinel_flows.ipc"):
    if not HAS_ZMQ:
        print("Error: pyzmq not installed.", file=sys.stderr)
        sys.exit(1)

    context = zmq.Context()
    subscriber = context.socket(zmq.SUB)
    subscriber.connect(endpoint)
    subscriber.setsockopt_string(zmq.SUBSCRIBE, "")
    print(f"[Detector] Subscribed to ZeroMQ flow stream at {endpoint}")

    try:
        while True:
            msg = subscriber.recv_string()
            data = json.loads(msg)
            is_anomaly, prob, attack_type = detector.predict(data)
            
            src = f"{data.get('srcIp', '?')}:{data.get('srcPort', 0)}"
            dst = f"{data.get('dstIp', '?')}:{data.get('dstPort', 0)}"
            proto = data.get('protocol', 6)

            if is_anomaly:
                print(f"\033[1;31m[ALERT] {attack_type.upper()} DETECTED!\033[0m {src} -> {dst} (Proto: {proto}) | Threat Score: {prob*100:.1f}%")
            else:
                print(f"[BENIGN] {src} -> {dst} | Threat Score: {prob*100:.1f}%")
    except KeyboardInterrupt:
        print("\n[Detector] Stopped.")
    finally:
        subscriber.close()
        context.term()

def run_file_watcher(detector, csv_path="Data/packet_data.csv", poll_interval=1.0):
    print(f"[Detector] Monitoring CSV file {csv_path} for newly expired flows...")
    if not os.path.exists(csv_path):
        print(f"[Detector] Waiting for {csv_path} to be created by NetSentinel...")
        while not os.path.exists(csv_path):
            time.sleep(poll_interval)

    with open(csv_path, "r") as f:
        # Seek to end of file to watch new lines
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line = line.strip()
            if not line or line.startswith("startTimeUnixMs"):
                continue

            parts = line.split(",")
            # Ensure line has required fields
            if len(parts) >= 19:
                try:
                    # Mapping from CSV schema
                    data = {
                        "startTimeUnixMs": float(parts[0]),
                        "srcIp": parts[1],
                        "dstIp": parts[2],
                        "srcPort": float(parts[3]),
                        "dstPort": float(parts[4]),
                        "protocol": float(parts[5]),
                        "duration": float(parts[6]),
                        "packets": float(parts[7]),
                        "bytes": float(parts[8]),
                        "packetsPerSecond": float(parts[9]),
                        "bytesPerSecond": float(parts[10]),
                        "averagePacketSize": float(parts[11]),
                        "synCount": float(parts[12]),
                        "ackCount": float(parts[13]),
                        "finCount": float(parts[14]),
                        "rstCount": float(parts[15]),
                        "pshCount": float(parts[16]),
                        "urgCount": float(parts[17]),
                    }
                    if len(parts) >= 22:
                        data["fwd_packets"] = float(parts[18])
                        data["fwd_bytes"] = float(parts[19])
                        data["bwd_packets"] = float(parts[20])
                        data["bwd_bytes"] = float(parts[21])
                    else:
                        data["fwd_packets"] = data["packets"]
                        data["fwd_bytes"] = data["bytes"]
                        data["bwd_packets"] = 0
                        data["bwd_bytes"] = 0

                    is_anomaly, prob, attack_type = detector.predict(data)
                    src = f"{data['srcIp']}:{int(data['srcPort'])}"
                    dst = f"{data['dstIp']}:{int(data['dstPort'])}"
                    proto = int(data['protocol'])

                    if is_anomaly:
                        print(f"\033[1;31m[ALERT] {attack_type.upper()} DETECTED!\033[0m {src} -> {dst} (Proto: {proto}) | Threat Score: {prob*100:.1f}%")
                    else:
                        print(f"[INFO ] Normal flow: {src} -> {dst} | Threat Score: {prob*100:.1f}%")
                except Exception as e:
                    print(f"Error parsing record: {e}", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSentinel Real-time ML Anomaly Detector")
    parser.add_argument("--mode", choices=["file", "zmq"], default="file", help="Input mode: watch CSV or listen to ZeroMQ")
    parser.add_argument("--model", choices=["xgb", "rf"], default="xgb", help="Model type: xgb or rf")
    parser.add_argument("--threshold", type=float, default=0.6, help="Anomaly probability threshold (0.0 - 1.0)")
    parser.add_argument("--file", default="Data/packet_data.csv", help="CSV path when in file mode")
    parser.add_argument("--endpoint", default="ipc:///tmp/netsentinel_flows.ipc", help="ZeroMQ endpoint when in zmq mode")

    args = parser.parse_args()
    det = AnomalyDetector(model_type=args.model, threshold=args.threshold)

    if args.mode == "zmq":
        run_zmq_listener(det, endpoint=args.endpoint)
    else:
        run_file_watcher(det, csv_path=args.file)
