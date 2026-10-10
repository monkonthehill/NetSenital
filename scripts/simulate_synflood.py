#!/usr/bin/env python3
"""
scripts/simulate_synflood.py

Simulates a volumetric embryonic TCP SYN flood against local loopback.
Emits non-blocking SYN connection requests without completing the 3-way handshake.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_attack import simulate_syn_flood

def main():
    parser = argparse.ArgumentParser(description="NetSentinel SYN Flood Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8999, help="Target port (default: 8999)")
    parser.add_argument("--count", type=int, default=100, help="Number of SYN packets (default: 100)")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between packets in seconds (default: 0.01)")
    args = parser.parse_args()

    simulate_syn_flood(host=args.target, port=args.port, count=args.count, delay=args.delay)

if __name__ == "__main__":
    main()
