#!/usr/bin/env python3
"""
scripts/simulate_udpflood.py

Simulates a volumetric UDP datagram flood against unassigned ports on local loopback.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_attack import simulate_udp_flood

def main():
    parser = argparse.ArgumentParser(description="NetSentinel UDP Flood Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=19999, help="Target port (default: 19999)")
    parser.add_argument("--count", type=int, default=120, help="Number of datagrams (default: 120)")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between packets in seconds (default: 0.01)")
    args = parser.parse_args()

    simulate_udp_flood(host=args.target, port=args.port, count=args.count, delay=args.delay)

if __name__ == "__main__":
    main()
