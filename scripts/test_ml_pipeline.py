#!/usr/bin/env python3
"""
scripts/test_ml_pipeline.py
Unit and integration test for the ML model pipeline.
"""
import os
import unittest
import pandas as pd
import numpy as np
import joblib
import xgboost as xgb

class TestMLPipeline(unittest.TestCase):
    def test_artifacts_exist(self):
        self.assertTrue(os.path.exists("models/rf_model.joblib"), "RF model must exist")
        self.assertTrue(os.path.exists("models/xgb_model.json"), "XGB model must exist")
        self.assertTrue(os.path.exists("models/feature_metadata.json"), "Feature metadata must exist")

    def test_model_loading_and_inference(self):
        rf = joblib.load("models/rf_model.joblib")
        xgb_model = xgb.XGBClassifier()
        xgb_model.load_model("models/xgb_model.json")

        # 19 features
        dummy_input = pd.DataFrame([np.zeros(19)], columns=[
            "srcPort", "dstPort", "protocol",
            "duration", "packets", "bytes", "packetsPerSecond", "bytesPerSecond",
            "averagePacketSize", "synCount", "ackCount", "finCount", "rstCount", "pshCount", "urgCount",
            "fwd_packets", "fwd_bytes", "bwd_packets", "bwd_bytes"
        ])

        rf_prob = rf.predict_proba(dummy_input)
        xgb_prob = xgb_model.predict_proba(dummy_input)

        self.assertEqual(rf_prob.shape, (1, 2))
        self.assertEqual(xgb_prob.shape, (1, 2))
        self.assertAlmostEqual(rf_prob[0].sum(), 1.0, places=4)
        self.assertAlmostEqual(xgb_prob[0].sum(), 1.0, places=4)

if __name__ == "__main__":
    unittest.main()
