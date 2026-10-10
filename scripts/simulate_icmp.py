#!/usr/bin/env python3
"""
scripts/simulate_icmp.py

Simulates an ICMP Flood echo request burst against local loopback using local ping.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_attack import simulate_icmp_flood

def main():
    parser = argparse.ArgumentParser(description="NetSentinel ICMP Flood Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--count", type=int, default=80, help="Number of ICMP packets (default: 80)")
    args = parser.parse_args()

    simulate_icmp_flood(host=args.target, count=args.count)

if __name__ == "__main__":
    main()
