#!/usr/bin/env python3
"""
scripts/simulate_slowloris.py

Simulates Slowloris HTTP resource exhaustion attack on local loopback.
Holds connections open by trickling periodic HTTP header lines at sub-PPS rates.
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_attack import simulate_slowloris, start_mock_slow_server

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Slowloris Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8888, help="Target port (default: 8888)")
    parser.add_argument("--sockets", type=int, default=15, help="Number of holding sockets (default: 15)")
    parser.add_argument("--duration", type=int, default=12, help="Holding duration in seconds (default: 12)")
    args = parser.parse_args()

    stop_event = threading.Event()
    server_thread = None
    if args.target in ("127.0.0.1", "localhost", "0.0.0.0"):
        server_thread = threading.Thread(
            target=start_mock_slow_server,
            args=(args.target, args.port, stop_event),
            daemon=True
        )
        server_thread.start()
        time.sleep(0.15)

    try:
        simulate_slowloris(host=args.target, port=args.port, sockets_count=args.sockets, duration_sec=args.duration)
    finally:
        if server_thread:
            stop_event.set()
            server_thread.join(timeout=0.5)

if __name__ == "__main__":
    main()
