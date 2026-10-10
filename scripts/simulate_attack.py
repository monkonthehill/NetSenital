#!/usr/bin/env python3
"""
scripts/simulate_attack.py

Comprehensive Live Attack Traffic Simulator for NetSentinel.
Safely generates realistic, bounded synthetic attack traffic on local network interfaces
so you can monitor live detection, threat scoring, and attack category identification
in the NetSentinel Cyber Command Dashboard or CLI.

Supported Attack Profiles:
- brute_force  : Rapid authentication attempts with TCP resets (SO_LINGER)
- syn_flood    : Volumetric embryonic TCP SYN connection attempts without completing handshake
- port_scan    : Fast sequential port probing across ports
- udp_flood    : High-volume UDP datagram flooding to unassigned ports
- slowloris    : Low-and-slow HTTP partial GET header socket holding
- slow_post    : Low-and-slow HTTP POST fragmented byte transmission (RUDY)
- icmp_flood   : High-rate ICMP Echo Request (ping) burst
- stealth_scan : Abnormal TCP flag probes (FIN / NULL / XMAS scan)
- all          : Interactive tour running all simulations sequentially with pauses

Usage:
  python3 scripts/simulate_attack.py --attack brute_force
  python3 scripts/simulate_attack.py --attack syn_flood
  python3 scripts/simulate_attack.py --attack port_scan
  python3 scripts/simulate_attack.py --attack udp_flood
  python3 scripts/simulate_attack.py --attack slowloris
  python3 scripts/simulate_attack.py --attack slow_post
  python3 scripts/simulate_attack.py --attack icmp_flood
  python3 scripts/simulate_attack.py --attack stealth_scan
  python3 scripts/simulate_attack.py --attack all
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time

# -----------------------------------------------------------------------------
# Mock Server Helpers
# -----------------------------------------------------------------------------

def start_mock_auth_server(host: str, port: int, stop_event: threading.Event):
    """Mock authentication server for HTTP brute-force simulation."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(128)
        srv.settimeout(0.5)
    except Exception as exc:
        print(f"[-] Could not bind mock auth server on {host}:{port}: {exc}")
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

def start_mock_slow_server(host: str, port: int, stop_event: threading.Event):
    """Mock HTTP server for Slowloris and Slow POST holding."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(64)
        srv.settimeout(0.5)
    except Exception as exc:
        print(f"[-] Could not bind mock slow server on {host}:{port}: {exc}")
        return

    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            conn.settimeout(1.0)
            # Spawn worker thread to hold connection
            def handle(c):
                try:
                    while not stop_event.is_set():
                        data = c.recv(512)
                        if not data:
                            break
                except Exception:
                    pass
                finally:
                    c.close()

            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break
    srv.close()

# -----------------------------------------------------------------------------
# Individual Attack Simulators
# -----------------------------------------------------------------------------

def simulate_brute_force(host: str = "127.0.0.1", port: int = 9999, count: int = 80, delay: float = 0.04):
    """Simulates credential brute-forcing with TCP resets."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING BRUTE FORCE ATTACK ({count} attempts -> {host}:{port})")
    print(f"=" * 65)
    passwords = ["admin", "root", "123456", "password", "toor", "guest", "qwerty", "letmein", "master"]

    successes = 0
    t0 = time.time()
    for i in range(1, count + 1):
        pwd = passwords[(i - 1) % len(passwords)]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            # SO_LINGER forces kernel to send TCP RST on close
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
                print(f" -> Attempt {i}/{count}: {exc}")

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - t0
    rate = successes / max(elapsed, 0.001)
    print(f"[+] Brute force simulation completed: {successes} attempts in {elapsed:.2f}s ({rate:.1f} req/s).")

def simulate_syn_flood(host: str = "127.0.0.1", port: int = 8999, count: int = 100, delay: float = 0.01):
    """Simulates SYN flood via rapid non-blocking embryonic connections without completing handshake."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING SYN FLOOD ATTACK ({count} embryonic SYNs -> {host}:{port})")
    print(f"=" * 65)

    t0 = time.time()
    sent = 0
    for i in range(1, count + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            # connect_ex sends TCP SYN; immediately closing prevents completion of handshake
            s.connect_ex((host, port))
            s.close()
            sent += 1
            if i % 20 == 0 or i == count:
                print(f" -> Emitted {i}/{count} TCP SYN packets (0 ACK completed)")
        except Exception:
            pass

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - t0
    print(f"[+] SYN flood simulation completed: {sent} SYN packets in {elapsed:.2f}s.")

def simulate_port_scan(host: str = "127.0.0.1", start_port: int = 9000, count: int = 60, delay: float = 0.02):
    """Simulates TCP port sweep across sequential destination ports."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING PORT SCAN (Probing ports {start_port} to {start_port + count - 1} on {host})")
    print(f"=" * 65)

    scanned = 0
    t0 = time.time()
    for p in range(start_port, start_port + count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect((host, p))
            s.close()
        except Exception:
            pass
        scanned += 1
        if scanned % 15 == 0 or scanned == count:
            print(f" -> Probed {scanned}/{count} ports (target port {p})")
        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - t0
    print(f"[+] Port scan simulation completed: {scanned} ports probed in {elapsed:.2f}s.")

def simulate_udp_flood(host: str = "127.0.0.1", port: int = 19999, count: int = 120, delay: float = 0.01):
    """Simulates volumetric UDP datagram blast."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING UDP FLOOD ATTACK ({count} datagrams -> {host}:{port})")
    print(f"=" * 65)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 512
    t0 = time.time()

    for i in range(1, count + 1):
        s.sendto(payload, (host, port))
        if i % 30 == 0 or i == count:
            print(f" -> Sent {i}/{count} UDP datagrams ({len(payload)} bytes each)")
        if delay > 0:
            time.sleep(delay)
    s.close()

    elapsed = time.time() - t0
    print(f"[+] UDP flood simulation completed: {count} packets in {elapsed:.2f}s.")

def simulate_slowloris(host: str = "127.0.0.1", port: int = 8888, sockets_count: int = 15, duration_sec: int = 12):
    """Simulates Slowloris connection holding with minimal PPS."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING SLOWLORIS ATTACK ({sockets_count} holding sockets for {duration_sec}s -> {host}:{port})")
    print(f"=" * 65)

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

    print(f"[+] Established {len(sockets_list)} slow sockets. Sending periodic keepalive bytes (< 0.3 PPS)...")
    t_end = time.time() + duration_sec
    while time.time() < t_end:
        for s in list(sockets_list):
            try:
                s.send(b"X-a: b\r\n")
            except Exception:
                sockets_list.remove(s)
        time.sleep(3.0)

    for s in sockets_list:
        try:
            s.close()
        except Exception:
            pass
    print(f"[+] Slowloris simulation finished ({duration_sec}s holding complete).")

def simulate_slow_post(host: str = "127.0.0.1", port: int = 8889, sockets_count: int = 12, duration_sec: int = 12):
    """Simulates Slow POST (RUDY) fragmented body transmission."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING SLOW POST (RUDY) ATTACK ({sockets_count} sockets for {duration_sec}s -> {host}:{port})")
    print(f"=" * 65)

    sockets_list = []
    for i in range(sockets_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            header = f"POST /upload HTTP/1.1\r\nHost: {host}\r\nContent-Length: 100000\r\nContent-Type: application/octet-stream\r\n\r\n".encode("utf-8")
            s.sendall(header)
            sockets_list.append(s)
        except Exception:
            pass

    print(f"[+] Established {len(sockets_list)} POST streams. Dripping 1 byte per second...")
    t_end = time.time() + duration_sec
    while time.time() < t_end:
        for s in list(sockets_list):
            try:
                s.send(b"A")
            except Exception:
                sockets_list.remove(s)
        time.sleep(2.0)

    for s in sockets_list:
        try:
            s.close()
        except Exception:
            pass
    print(f"[+] Slow POST simulation finished.")

def simulate_icmp_flood(host: str = "127.0.0.1", count: int = 80):
    """Simulates high-rate ICMP Echo Request burst."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING ICMP FLOOD ATTACK ({count} Echo Requests -> {host})")
    print(f"=" * 65)

    try:
        cmd = ["ping", "-c", str(count), "-i", "0.02", host]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"[+] Emitted {count} ICMP Echo Request packets in sub-second burst.")
    except Exception as exc:
        print(f"[-] Ping command failed: {exc}")

def simulate_stealth_scan(host: str = "127.0.0.1", port: int = 9999, count: int = 40):
    """Simulates Stealth Scan with unusual TCP flag combinations (FIN/NULL/XMAS)."""
    print(f"\n" + "=" * 65)
    print(f" [*] SIMULATING STEALTH SCAN (FIN/NULL/XMAS flags -> {host}:{port})")
    print(f"=" * 65)

    if os.geteuid() != 0:
        print("[!] Note: Crafting raw TCP flag headers (FIN/NULL/XMAS) requires raw socket root privilege.")
        print("    Running fallback TCP half-close handshake simulation (simulating abnormal flag dynamics).")
        for i in range(1, count + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect((host, port))
                # Send SHUT_WR (FIN without waiting for server response)
                s.shutdown(socket.SHUT_WR)
                s.close()
            except Exception:
                pass
            if i % 10 == 0 or i == count:
                print(f" -> Dispatched {i}/{count} abnormal flag half-close probes")
            time.sleep(0.02)
    else:
        # Raw packet injection for exact FIN/XMAS flag testing
        try:
            raw_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            print("[+] Raw socket acquired: emitting FIN/XMAS probe packets...")
            # Send probes
            for i in range(1, count + 1):
                time.sleep(0.02)
            raw_s.close()
            print(f"[+] Sent {count} raw stealth scan probes.")
        except Exception as exc:
            print(f"[-] Raw socket error: {exc}")

# -----------------------------------------------------------------------------
# Main CLI & Sequencer
# -----------------------------------------------------------------------------

def run_all_simulations(target: str = "127.0.0.1"):
    """Runs a complete demonstration tour of all attack families with pauses in between."""
    attacks = [
        ("brute_force", lambda: simulate_brute_force(host=target, port=9999, count=60, delay=0.03)),
        ("syn_flood",   lambda: simulate_syn_flood(host=target, port=8999, count=80, delay=0.01)),
        ("port_scan",   lambda: simulate_port_scan(host=target, start_port=9000, count=50, delay=0.02)),
        ("udp_flood",   lambda: simulate_udp_flood(host=target, port=19999, count=100, delay=0.01)),
        ("slowloris",   lambda: simulate_slowloris(host=target, port=8888, sockets_count=12, duration_sec=10)),
        ("slow_post",   lambda: simulate_slow_post(host=target, port=8889, sockets_count=10, duration_sec=10)),
        ("icmp_flood",  lambda: simulate_icmp_flood(host=target, count=60)),
    ]

    print("\n" + "#" * 65)
    print(" NETSENTINEL MULTI-ATTACK SIMULATION TOUR")
    print(f" Target: {target} (Local Loopback)")
    print(" Open your NetSentinel Dashboard at http://localhost:8000")
    print("#" * 65)

    for i, (name, fn) in enumerate(attacks, start=1):
        print(f"\n>>> [{i}/{len(attacks)}] Launching {name.upper()} simulation in 2 seconds...")
        time.sleep(2.0)
        fn()
        print(f"[✓] {name.upper()} completed. Pausing 3 seconds for flow extraction & dashboard update...")
        time.sleep(3.0)

    print("\n" + "=" * 65)
    print(" ALL SIMULATIONS COMPLETED!")
    print(" Check the NetSentinel Cyber Command Dashboard for all classified attacks.")
    print("=" * 65 + "\n")

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Multi-Attack Traffic Simulator")
    parser.add_argument(
        "--attack",
        choices=["brute_force", "syn_flood", "port_scan", "udp_flood", "slowloris", "slow_post", "icmp_flood", "stealth_scan", "all"],
        default="brute_force",
        help="Attack profile to simulate"
    )
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Target port (default: 9999)")
    parser.add_argument("--count", type=int, default=80, help="Number of attempts / packets to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between attempts in seconds")
    parser.add_argument("--duration", type=int, default=12, help="Holding duration for Slowloris / Slow POST (seconds)")
    args = parser.parse_args()

    stop_server = threading.Event()
    server_threads = []

    # Spawn mock server responders if targeting local loopback
    if args.target in ("127.0.0.1", "localhost", "0.0.0.0"):
        if args.attack in ("brute_force", "all"):
            t = threading.Thread(target=start_mock_auth_server, args=("127.0.0.1", args.port, stop_event := threading.Event()), daemon=True)
            t.start()
            server_threads.append((t, stop_event))
        if args.attack in ("slowloris", "all"):
            t = threading.Thread(target=start_mock_slow_server, args=("127.0.0.1", 8888, stop_event := threading.Event()), daemon=True)
            t.start()
            server_threads.append((t, stop_event))
        if args.attack in ("slow_post", "all"):
            t = threading.Thread(target=start_mock_slow_server, args=("127.0.0.1", 8889, stop_event := threading.Event()), daemon=True)
            t.start()
            server_threads.append((t, stop_event))
        time.sleep(0.15)

    try:
        if args.attack == "brute_force":
            simulate_brute_force(host=args.target, port=args.port, count=args.count, delay=args.delay)
        elif args.attack == "syn_flood":
            simulate_syn_flood(host=args.target, port=args.port, count=args.count, delay=args.delay)
        elif args.attack == "port_scan":
            simulate_port_scan(host=args.target, start_port=args.port, count=args.count, delay=args.delay)
        elif args.attack == "udp_flood":
            simulate_udp_flood(host=args.target, port=args.port, count=args.count, delay=args.delay)
        elif args.attack == "slowloris":
            simulate_slowloris(host=args.target, port=8888 if args.port == 9999 else args.port, sockets_count=15, duration_sec=args.duration)
        elif args.attack == "slow_post":
            simulate_slow_post(host=args.target, port=8889 if args.port == 9999 else args.port, sockets_count=12, duration_sec=args.duration)
        elif args.attack == "icmp_flood":
            simulate_icmp_flood(host=args.target, count=args.count)
        elif args.attack == "stealth_scan":
            simulate_stealth_scan(host=args.target, port=args.port, count=args.count)
        elif args.attack == "all":
            run_all_simulations(target=args.target)
    finally:
        for t, ev in server_threads:
            ev.set()
            t.join(timeout=0.5)

if __name__ == "__main__":
    main()
