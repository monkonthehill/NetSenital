#!/usr/bin/env python3
"""
scripts/test_ml_pipeline.py
Unit and integration test for the ML model pipeline, threat classification, and attack categorization.
"""
import json
import os
import unittest
import pandas as pd
import numpy as np
import joblib
import xgboost as xgb

FEATURE_COLS = [
    "srcPort", "dstPort", "protocol",
    "duration", "packets", "bytes", "packetsPerSecond", "bytesPerSecond",
    "averagePacketSize", "synCount", "ackCount", "finCount", "rstCount", "pshCount", "urgCount",
    "fwd_packets", "fwd_bytes", "bwd_packets", "bwd_bytes"
]

class TestMLPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rf = joblib.load("models/rf_model.joblib")
        cls.xgb_model = xgb.XGBClassifier()
        cls.xgb_model.load_model("models/xgb_model.json")
        cls.cat_model = xgb.XGBClassifier()
        cls.cat_model.load_model("models/category_model.json")
        with open("models/attack_classes.json") as f:
            cls.classes = {int(k): str(v) for k, v in json.load(f).items()}

    def test_artifacts_exist(self):
        self.assertTrue(os.path.exists("models/rf_model.joblib"), "RF model must exist")
        self.assertTrue(os.path.exists("models/xgb_model.json"), "XGB model must exist")
        self.assertTrue(os.path.exists("models/category_model.json"), "Category model must exist")
        self.assertTrue(os.path.exists("models/attack_classes.json"), "Attack classes JSON must exist")
        self.assertTrue(os.path.exists("models/feature_metadata.json"), "Feature metadata must exist")

    def test_model_loading_and_inference(self):
        dummy_input = pd.DataFrame([np.zeros(19)], columns=FEATURE_COLS)
        rf_prob = self.rf.predict_proba(dummy_input)
        xgb_prob = self.xgb_model.predict_proba(dummy_input)
        cat_prob = self.cat_model.predict_proba(dummy_input)

        self.assertEqual(rf_prob.shape, (1, 2))
        self.assertEqual(xgb_prob.shape, (1, 2))
        self.assertEqual(cat_prob.shape, (1, 9))
        self.assertAlmostEqual(rf_prob[0].sum(), 1.0, places=4)
        self.assertAlmostEqual(xgb_prob[0].sum(), 1.0, places=4)
        self.assertAlmostEqual(cat_prob[0].sum(), 1.0, places=4)

    def test_benign_traffic_scenarios(self):
        """Ensure realistic benign traffic scenarios are classified as benign with threat < 0.20."""
        benign_scenarios = [
            # Benign HTTPS
            [54321, 443, 6, 2.5, 30, 25000, 12.0, 10000.0, 833.3, 1, 29, 1, 0, 8, 0, 10, 3000, 20, 22000],
            # Benign DNS
            [51234, 53, 17, 0.025, 2, 160, 80.0, 6400.0, 80.0, 0, 0, 0, 0, 0, 0, 1, 60, 1, 100],
            # Benign TCP Ping / Health Check
            [60001, 8080, 6, 0.005, 3, 180, 600.0, 36000.0, 60.0, 1, 2, 1, 0, 0, 0, 2, 120, 1, 60],
            # Benign SSH Interactive
            [50230, 22, 6, 30.0, 120, 14000, 4.0, 466.6, 116.6, 1, 119, 1, 0, 45, 0, 50, 4000, 70, 10000]
        ]
        df = pd.DataFrame(benign_scenarios, columns=FEATURE_COLS)
        xgb_threats = self.xgb_model.predict_proba(df)[:, 1]
        rf_threats = self.rf.predict_proba(df)[:, 1]

        for i, (xgb_t, rf_t) in enumerate(zip(xgb_threats, rf_threats)):
            self.assertLess(xgb_t, 0.20, f"Benign scenario {i} XGB threat too high: {xgb_t:.4f}")
            self.assertLess(rf_t, 0.20, f"Benign scenario {i} RF threat too high: {rf_t:.4f}")

    def test_attack_traffic_scenarios(self):
        """Ensure diverse attack families are classified as attacks with threat > 0.80."""
        attack_scenarios = [
            # SYN Flood: high PPS, 100% SYN, 0 bwd
            [49999, 80, 6, 0.08, 50, 3000, 625.0, 37500.0, 60.0, 50, 0, 0, 0, 0, 0, 50, 3000, 0, 0],
            # Port Scan: single probe, 0 bwd
            [58210, 23, 6, 0.002, 1, 60, 500.0, 30000.0, 60.0, 1, 0, 0, 0, 0, 0, 1, 60, 0, 0],
            # Stealth FIN Scan: FIN flag, 0 SYN, 0 ACK
            [58211, 80, 6, 0.001, 1, 44, 1000.0, 44000.0, 44.0, 0, 0, 1, 0, 0, 0, 1, 44, 0, 0],
            # UDP Flood: 0 handshakes, large volume, 0 bwd
            [53200, 12345, 17, 0.15, 60, 30000, 400.0, 200000.0, 500.0, 0, 0, 0, 0, 0, 0, 60, 30000, 0, 0],
            # Slowloris: prolonged duration, very low PPS, minimal bwd
            [52100, 80, 6, 45.0, 12, 900, 0.26, 20.0, 75.0, 1, 11, 0, 0, 6, 0, 12, 900, 0, 0],
            # Brute Force: repeated resets (RST >= 1)
            [55440, 22, 6, 0.45, 18, 2200, 40.0, 4888.8, 122.2, 1, 15, 0, 2, 4, 0, 10, 1200, 8, 1000],
            # ICMP Flood: protocol 1, port 0, high PPS
            [0, 0, 1, 0.05, 100, 6400, 2000.0, 128000.0, 64.0, 0, 0, 0, 0, 0, 0, 100, 6400, 0, 0]
        ]
        df = pd.DataFrame(attack_scenarios, columns=FEATURE_COLS)
        xgb_threats = self.xgb_model.predict_proba(df)[:, 1]
        rf_threats = self.rf.predict_proba(df)[:, 1]

        for i, (xgb_t, rf_t) in enumerate(zip(xgb_threats, rf_threats)):
            self.assertGreater(xgb_t, 0.80, f"Attack scenario {i} XGB threat too low: {xgb_t:.4f}")
            self.assertGreater(rf_t, 0.80, f"Attack scenario {i} RF threat too low: {rf_t:.4f}")

    def test_attack_category_classification(self):
        """Ensure multiclass category model accurately identifies the specific attack category."""
        test_cases = [
            ("SYN Flood", [49999, 80, 6, 0.08, 50, 3000, 625.0, 37500.0, 60.0, 50, 0, 0, 0, 0, 0, 50, 3000, 0, 0]),
            ("SYN Flood", [45000, 8999, 6, 0.0005, 2, 114, 4000.0, 228000.0, 57.0, 1, 1, 0, 1, 0, 0, 1, 60, 1, 54]),
            ("Port Scan", [58210, 12345, 6, 0.002, 1, 60, 500.0, 30000.0, 60.0, 1, 0, 0, 0, 0, 0, 1, 60, 0, 0]),
            ("Stealth Scan", [58211, 80, 6, 0.001, 1, 44, 1000.0, 44000.0, 44.0, 0, 0, 1, 0, 0, 0, 1, 44, 0, 0]),
            ("UDP Flood", [53200, 12345, 17, 0.15, 60, 30000, 400.0, 200000.0, 500.0, 0, 0, 0, 0, 0, 0, 60, 30000, 0, 0]),
            ("Slowloris", [52100, 80, 6, 45.0, 12, 900, 0.26, 20.0, 75.0, 1, 11, 0, 0, 6, 0, 12, 900, 0, 0]),
            ("Slowloris", [45001, 8888, 6, 12.0, 6, 420, 0.5, 35.0, 70.0, 1, 5, 0, 0, 3, 0, 6, 420, 0, 0]),
            ("Brute Force", [55440, 22, 6, 0.45, 18, 2200, 40.0, 4888.8, 122.2, 1, 15, 0, 2, 4, 0, 10, 1200, 8, 1000]),
            ("ICMP Flood", [0, 0, 1, 0.05, 100, 6400, 2000.0, 128000.0, 64.0, 0, 0, 0, 0, 0, 0, 100, 6400, 0, 0])
        ]

        for expected_cat, features in test_cases:
            df = pd.DataFrame([features], columns=FEATURE_COLS)
            pred_id = int(self.cat_model.predict(df)[0])
            pred_name = self.classes.get(pred_id, "Unknown")
            self.assertEqual(pred_name, expected_cat, f"Expected {expected_cat}, got {pred_name}")

if __name__ == "__main__":
    unittest.main()
