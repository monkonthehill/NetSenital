#!/usr/bin/env python3
"""
scripts/simulate_stealthscan.py

Simulates abnormal TCP flag stealth probes (FIN / half-close) against local loopback.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_attack import simulate_stealth_scan

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Stealth Scan Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Target port (default: 9999)")
    parser.add_argument("--count", type=int, default=40, help="Number of probe packets (default: 40)")
    args = parser.parse_args()

    simulate_stealth_scan(host=args.target, port=args.port, count=args.count)

if __name__ == "__main__":
    main()
