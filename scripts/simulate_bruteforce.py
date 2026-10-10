#!/usr/bin/env python3
"""
scripts/simulate_bruteforce.py

Simulates a rapid credential brute-force attack against local loopback.
Generates rapid authentication attempts with TCP resets (SO_LINGER RST).
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_attack import simulate_brute_force, start_mock_auth_server

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Brute Force Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Target port (default: 9999)")
    parser.add_argument("--count", type=int, default=80, help="Number of attempts (default: 80)")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between attempts in seconds (default: 0.03)")
    args = parser.parse_args()

    stop_event = threading.Event()
    server_thread = None
    if args.target in ("127.0.0.1", "localhost", "0.0.0.0"):
        server_thread = threading.Thread(
            target=start_mock_auth_server,
            args=(args.target, args.port, stop_event),
            daemon=True
        )
        server_thread.start()
        time.sleep(0.15)

    try:
        simulate_brute_force(host=args.target, port=args.port, count=args.count, delay=args.delay)
    finally:
        if server_thread:
            stop_event.set()
            server_thread.join(timeout=0.5)

if __name__ == "__main__":
    main()
