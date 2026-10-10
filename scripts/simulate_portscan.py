#!/usr/bin/env python3
"""
scripts/simulate_portscan.py

Simulates a fast TCP port scan sweep across consecutive ports on local loopback.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_attack import simulate_port_scan

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Port Scan Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--start-port", type=int, default=9000, help="Starting destination port (default: 9000)")
    parser.add_argument("--count", type=int, default=60, help="Number of ports to sweep (default: 60)")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between probes in seconds (default: 0.02)")
    args = parser.parse_args()

    simulate_port_scan(host=args.target, start_port=args.start_port, count=args.count, delay=args.delay)

if __name__ == "__main__":
    main()
