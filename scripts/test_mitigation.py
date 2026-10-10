#!/usr/bin/env python3
"""
scripts/test_mitigation.py
Unit test for FirewallMitigationManager auto-blocking and automatic cooldown unblocking.
"""
import os
import sys
import time
import unittest
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web_app import FirewallMitigationManager

class TestFirewallMitigation(unittest.TestCase):
    def setUp(self):
        self.mgr = FirewallMitigationManager()
        self.mgr.cooldown_sec = 1  # 1 second for fast test

    def test_block_and_is_blocked(self):
        ip = "192.168.1.105"
        self.assertFalse(self.mgr.is_blocked(ip))
        entry = self.mgr.block_ip(ip, reason="SYN Flood", threat_score=1.0)
        self.assertIsNotNone(entry)
        self.assertTrue(self.mgr.is_blocked(ip))
        self.assertEqual(entry["reason"], "SYN Flood")
        self.assertEqual(entry["threat_score"], 1.0)
        self.assertFalse(entry["is_whitelisted"])

    def test_whitelist_protection(self):
        # Localhost / loopback should be protected
        entry = self.mgr.block_ip("127.0.0.1", reason="SYN Flood", threat_score=1.0)
        self.assertTrue(entry["is_whitelisted"])
        self.assertFalse(entry["os_rule_applied"])
        self.assertTrue(self.mgr.is_blocked("127.0.0.1"))

    def test_manual_unblock(self):
        ip = "10.0.0.99"
        self.mgr.block_ip(ip, reason="Brute Force", threat_score=0.99)
        self.assertTrue(self.mgr.is_blocked(ip))
        success = self.mgr.unblock_ip(ip)
        self.assertTrue(success)
        self.assertFalse(self.mgr.is_blocked(ip))

    def test_auto_cooldown_unblock(self):
        ip = "172.16.0.40"
        self.mgr.block_ip(ip, reason="Slowloris", threat_score=1.0)
        self.assertTrue(self.mgr.is_blocked(ip))
        # Wait 1.1s for cooldown to elapse
        time.sleep(1.15)
        self.assertFalse(self.mgr.is_blocked(ip), "IP should be automatically unblocked after cooldown")

    def test_status_reporting(self):
        ip = "192.168.100.5"
        self.mgr.cooldown_sec = 60
        self.mgr.block_ip(ip, reason="ICMP Flood", threat_score=1.0)
        status = self.mgr.get_status()
        self.assertEqual(status["total_blocked"], 1)
        self.assertEqual(status["blocked"][0]["ip"], ip)
        self.assertGreater(status["blocked"][0]["remaining_sec"], 50)

if __name__ == "__main__":
    unittest.main()
