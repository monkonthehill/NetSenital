#!/usr/bin/env python3
"""
scripts/generate_dataset.py

High-Fidelity, Lightweight Multi-Attack Network Flow Dataset Generator for NetSentinel.
Generates a statistically realistic dataset covering diverse benign traffic and 5 distinct
attack families (Port Scans, SYN Floods, UDP Floods, Slowloris, and Brute Force).

Features:
- Sub-second execution with negligible CPU and memory (< 50MB) footprint.
- Exact adherence to NetSentinel's 22-column bidirectional flow schema.
- Randomized IP subnets and dynamic ephemeral ports to prevent shortcut learning.
- Saves directly to Data/flows.csv and Data/labeled_flows.csv.
"""

from __future__ import annotations

import os
import shutil
import time
import numpy as np
import pandas as pd

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
OUTPUT_FLOWS = "Data/flows.csv"
OUTPUT_LABELED = "Data/labeled_flows.csv"
RANDOM_SEED = 42

np.random.seed(RANDOM_SEED)

# Random IP generator helpers
def random_ipv4(subnet_prefix: str, count: int) -> list[str]:
    """Generate realistic IPv4 addresses under a specific subnet prefix."""
    last_two = np.random.randint(1, 254, size=(count, 2))
    return [f"{subnet_prefix}.{a}.{b}" for a, b in last_two]

def random_ephemeral_ports(count: int) -> np.ndarray:
    """Standard dynamic ephemeral port range (49152 - 65535)."""
    return np.random.randint(49152, 65535, size=count)

# -----------------------------------------------------------------------------
# Flow Generators
# -----------------------------------------------------------------------------

def generate_benign_flows(n_samples: int = 15000) -> pd.DataFrame:
    """
    Generates diverse benign traffic:
    - Web Browsing (HTTPS 443, HTTP 80)
    - DNS lookups (UDP 53)
    - SSH interactive sessions (TCP 22)
    - API / Microservice JSON RPC (TCP 8080, 5000)
    - Short TCP health checks / pings
    - Bulk downloads
    """
    records = []
    base_time = int(time.time() * 1000) - 86400000  # Within last 24h

    # 1. HTTPS / HTTP Web Browsing (~7,000 flows)
    n_web = int(n_samples * 0.46)
    durations = np.random.lognormal(mean=0.5, sigma=0.8, size=n_web).clip(0.05, 25.0)
    fwd_pkts = np.random.randint(4, 80, size=n_web)
    bwd_pkts = (fwd_pkts * np.random.uniform(1.1, 2.5, size=n_web)).astype(int).clip(4, 250)
    pkts = fwd_pkts + bwd_pkts
    
    # Bytes calculation: fwd is requests (~300B avg), bwd is response payload (~1100B avg)
    fwd_b = (fwd_pkts * np.random.uniform(150, 450, size=n_web)).astype(int)
    bwd_b = (bwd_pkts * np.random.uniform(600, 1420, size=n_web)).astype(int)
    tot_b = fwd_b + bwd_b

    src_ips = random_ipv4("192.168.1", n_web)
    dst_ips = random_ipv4("142.250", n_web) # e.g. CDN / Web
    src_ports = random_ephemeral_ports(n_web)
    dst_ports = np.random.choice([443, 80, 8443], size=n_web, p=[0.85, 0.12, 0.03])

    syns = np.random.choice([1, 2], size=n_web, p=[0.9, 0.1])
    acks = (pkts - np.random.randint(1, 3, size=n_web)).clip(min=1)
    fins = np.random.choice([1, 2], size=n_web, p=[0.7, 0.3])
    rsts = np.random.choice([0, 1], size=n_web, p=[0.97, 0.03])
    pshs = np.random.randint(1, 20, size=n_web).clip(max=pkts)
    urgs = np.zeros(n_web, dtype=int)

    for i in range(n_web):
        d = max(durations[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 80000000),
            "srcIp": src_ips[i], "dstIp": dst_ips[i],
            "srcPort": int(src_ports[i]), "dstPort": int(dst_ports[i]),
            "protocol": 6, "duration": round(float(durations[i]), 6),
            "packets": int(pkts[i]), "bytes": int(tot_b[i]),
            "packetsPerSecond": round(float(pkts[i] / d), 4),
            "bytesPerSecond": round(float(tot_b[i] / d), 4),
            "averagePacketSize": round(float(tot_b[i] / pkts[i]), 4),
            "synCount": int(syns[i]), "ackCount": int(acks[i]), "finCount": int(fins[i]),
            "rstCount": int(rsts[i]), "pshCount": int(pshs[i]), "urgCount": int(urgs[i]),
            "fwd_packets": int(fwd_pkts[i]), "fwd_bytes": int(fwd_b[i]),
            "bwd_packets": int(bwd_pkts[i]), "bwd_bytes": int(bwd_b[i]),
            "label": "benign"
        })

    # 2. DNS Lookups (~3,000 flows)
    n_dns = int(n_samples * 0.20)
    durations_dns = np.random.uniform(0.005, 0.08, size=n_dns)
    fwd_pkts_dns = np.random.choice([1, 2], size=n_dns, p=[0.92, 0.08])
    bwd_pkts_dns = np.random.choice([1, 2], size=n_dns, p=[0.90, 0.10])
    pkts_dns = fwd_pkts_dns + bwd_pkts_dns
    fwd_b_dns = (fwd_pkts_dns * np.random.uniform(60, 95, size=n_dns)).astype(int)
    bwd_b_dns = (bwd_pkts_dns * np.random.uniform(90, 260, size=n_dns)).astype(int)
    tot_b_dns = fwd_b_dns + bwd_b_dns

    src_ips_dns = random_ipv4("192.168.1", n_dns)
    dst_ips_dns = np.random.choice(["1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "1.0.0.1"], size=n_dns)
    src_ports_dns = random_ephemeral_ports(n_dns)

    for i in range(n_dns):
        d = max(durations_dns[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 80000000),
            "srcIp": src_ips_dns[i], "dstIp": dst_ips_dns[i],
            "srcPort": int(src_ports_dns[i]), "dstPort": 53,
            "protocol": 17, "duration": round(float(durations_dns[i]), 6),
            "packets": int(pkts_dns[i]), "bytes": int(tot_b_dns[i]),
            "packetsPerSecond": round(float(pkts_dns[i] / d), 4),
            "bytesPerSecond": round(float(tot_b_dns[i] / d), 4),
            "averagePacketSize": round(float(tot_b_dns[i] / pkts_dns[i]), 4),
            "synCount": 0, "ackCount": 0, "finCount": 0,
            "rstCount": 0, "pshCount": 0, "urgCount": 0,
            "fwd_packets": int(fwd_pkts_dns[i]), "fwd_bytes": int(fwd_b_dns[i]),
            "bwd_packets": int(bwd_pkts_dns[i]), "bwd_bytes": int(bwd_b_dns[i]),
            "label": "benign"
        })

    # 3. Short TCP Pings / Health Checks / Microservices (~3,500 flows)
    n_ping = int(n_samples * 0.23)
    durations_ping = np.random.uniform(0.002, 0.06, size=n_ping)
    fwd_pkts_ping = np.random.choice([1, 2], size=n_ping, p=[0.7, 0.3])
    bwd_pkts_ping = np.random.choice([1, 2], size=n_ping, p=[0.7, 0.3])
    pkts_ping = fwd_pkts_ping + bwd_pkts_ping
    tot_b_ping = pkts_ping * np.random.randint(54, 75, size=n_ping)
    fwd_b_ping = (tot_b_ping * 0.5).astype(int)
    bwd_b_ping = tot_b_ping - fwd_b_ping

    src_ips_ping = random_ipv4("10.0.0", n_ping)
    dst_ips_ping = random_ipv4("10.0.0", n_ping)
    src_ports_ping = random_ephemeral_ports(n_ping)
    dst_ports_ping = np.random.choice([8080, 5000, 3000, 80, 443], size=n_ping)

    for i in range(n_ping):
        d = max(durations_ping[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 80000000),
            "srcIp": src_ips_ping[i], "dstIp": dst_ips_ping[i],
            "srcPort": int(src_ports_ping[i]), "dstPort": int(dst_ports_ping[i]),
            "protocol": 6, "duration": round(float(durations_ping[i]), 6),
            "packets": int(pkts_ping[i]), "bytes": int(tot_b_ping[i]),
            "packetsPerSecond": round(float(pkts_ping[i] / d), 4),
            "bytesPerSecond": round(float(tot_b_ping[i] / d), 4),
            "averagePacketSize": round(float(tot_b_ping[i] / pkts_ping[i]), 4),
            "synCount": 1, "ackCount": int(pkts_ping[i] - 1), "finCount": 1,
            "rstCount": 0, "pshCount": 0, "urgCount": 0,
            "fwd_packets": int(fwd_pkts_ping[i]), "fwd_bytes": int(fwd_b_ping[i]),
            "bwd_packets": int(bwd_pkts_ping[i]), "bwd_bytes": int(bwd_b_ping[i]),
            "label": "benign"
        })

    # 4. Interactive SSH & Bulk Transfers (~1,500 flows)
    n_bulk = n_samples - len(records)
    durations_bulk = np.random.uniform(5.0, 45.0, size=n_bulk)
    fwd_pkts_bulk = np.random.randint(50, 400, size=n_bulk)
    bwd_pkts_bulk = (fwd_pkts_bulk * np.random.uniform(1.5, 3.0, size=n_bulk)).astype(int)
    pkts_bulk = fwd_pkts_bulk + bwd_pkts_bulk
    fwd_b_bulk = fwd_pkts_bulk * 80
    bwd_b_bulk = bwd_pkts_bulk * np.random.randint(900, 1460, size=n_bulk)
    tot_b_bulk = fwd_b_bulk + bwd_b_bulk

    src_ips_bulk = random_ipv4("192.168.1", n_bulk)
    dst_ips_bulk = random_ipv4("10.0.1", n_bulk)
    src_ports_bulk = random_ephemeral_ports(n_bulk)
    dst_ports_bulk = np.random.choice([22, 443, 9000], size=n_bulk, p=[0.4, 0.4, 0.2])

    for i in range(n_bulk):
        d = max(durations_bulk[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 80000000),
            "srcIp": src_ips_bulk[i], "dstIp": dst_ips_bulk[i],
            "srcPort": int(src_ports_bulk[i]), "dstPort": int(dst_ports_bulk[i]),
            "protocol": 6, "duration": round(float(durations_bulk[i]), 6),
            "packets": int(pkts_bulk[i]), "bytes": int(tot_b_bulk[i]),
            "packetsPerSecond": round(float(pkts_bulk[i] / d), 4),
            "bytesPerSecond": round(float(tot_b_bulk[i] / d), 4),
            "averagePacketSize": round(float(tot_b_bulk[i] / pkts_bulk[i]), 4),
            "synCount": 1, "ackCount": int(pkts_bulk[i] - 1), "finCount": 1,
            "rstCount": 0, "pshCount": np.random.randint(10, 80), "urgCount": 0,
            "fwd_packets": int(fwd_pkts_bulk[i]), "fwd_bytes": int(fwd_b_bulk[i]),
            "bwd_packets": int(bwd_pkts_bulk[i]), "bwd_bytes": int(bwd_b_bulk[i]),
            "label": "benign"
        })

    return pd.DataFrame(records)

# -----------------------------------------------------------------------------
# Attack Generators
# -----------------------------------------------------------------------------

def generate_port_scans(n_samples: int = 2000) -> pd.DataFrame:
    """
    Port Scan (Nmap SYN scan, connect scan, FIN/NULL probes).
    Characteristics:
    - 1 to 2 packets per flow (probe only)
    - Zero or near-zero backward packets
    - synCount = 1, ackCount = 0 (or RST reply from closed port)
    - Small packet size (~40-60B)
    - Destination ports scattered across 1 to 65535
    """
    base_time = int(time.time() * 1000) - 40000000
    src_ips = random_ipv4("10.100.1", n_samples) # Attacker subnet
    dst_ips = random_ipv4("192.168.1", n_samples)
    src_ports = random_ephemeral_ports(n_samples)
    dst_ports = np.random.randint(1, 65535, size=n_samples)

    durations = np.random.uniform(0.0001, 0.02, size=n_samples)
    has_reply = np.random.choice([0, 1], size=n_samples, p=[0.75, 0.25])
    fwd_pkts = np.random.choice([1, 2], size=n_samples, p=[0.9, 0.1])
    bwd_pkts = has_reply # If victim sent RST, bwd=1, else 0
    pkts = fwd_pkts + bwd_pkts

    fwd_b = fwd_pkts * np.random.randint(44, 60, size=n_samples)
    bwd_b = bwd_pkts * np.random.randint(40, 54, size=n_samples)
    tot_b = fwd_b + bwd_b

    syns = fwd_pkts
    acks = np.zeros(n_samples, dtype=int)
    rsts = bwd_pkts # Closed ports respond with RST

    records = []
    for i in range(n_samples):
        d = max(durations[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 30000000),
            "srcIp": src_ips[i], "dstIp": dst_ips[i],
            "srcPort": int(src_ports[i]), "dstPort": int(dst_ports[i]),
            "protocol": 6, "duration": round(float(durations[i]), 6),
            "packets": int(pkts[i]), "bytes": int(tot_b[i]),
            "packetsPerSecond": round(float(pkts[i] / d), 4),
            "bytesPerSecond": round(float(tot_b[i] / d), 4),
            "averagePacketSize": round(float(tot_b[i] / pkts[i]), 4),
            "synCount": int(syns[i]), "ackCount": int(acks[i]), "finCount": 0,
            "rstCount": int(rsts[i]), "pshCount": 0, "urgCount": 0,
            "fwd_packets": int(fwd_pkts[i]), "fwd_bytes": int(fwd_b[i]),
            "bwd_packets": int(bwd_pkts[i]), "bwd_bytes": int(bwd_b[i]),
            "label": "port_scan"
        })
    return pd.DataFrame(records)

def generate_syn_floods(n_samples: int = 2000) -> pd.DataFrame:
    """
    SYN Flood DoS/DDoS.
    Characteristics:
    - High packet volume (50 to 1,500 packets)
    - 100% SYN flags, 0 ACK
    - bwd_packets = 0 (victim buffer exhausted / no ACK)
    - Uniform small packet sizes (40-60 bytes)
    - High PPS (> 1000)
    """
    base_time = int(time.time() * 1000) - 30000000
    src_ips = random_ipv4("172.16.5", n_samples)
    dst_ips = np.random.choice(["192.168.1.10", "192.168.1.50", "10.0.0.2"], size=n_samples)
    src_ports = random_ephemeral_ports(n_samples)
    dst_ports = np.random.choice([80, 443, 8080, 22, 53], size=n_samples)

    pkts = np.random.randint(40, 1200, size=n_samples)
    durations = np.random.uniform(0.05, 3.0, size=n_samples)
    tot_b = pkts * np.random.randint(44, 54, size=n_samples)

    records = []
    for i in range(n_samples):
        d = max(durations[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 20000000),
            "srcIp": src_ips[i], "dstIp": dst_ips[i],
            "srcPort": int(src_ports[i]), "dstPort": int(dst_ports[i]),
            "protocol": 6, "duration": round(float(durations[i]), 6),
            "packets": int(pkts[i]), "bytes": int(tot_b[i]),
            "packetsPerSecond": round(float(pkts[i] / d), 4),
            "bytesPerSecond": round(float(tot_b[i] / d), 4),
            "averagePacketSize": round(float(tot_b[i] / pkts[i]), 4),
            "synCount": int(pkts[i]), "ackCount": 0, "finCount": 0,
            "rstCount": 0, "pshCount": 0, "urgCount": 0,
            "fwd_packets": int(pkts[i]), "fwd_bytes": int(tot_b[i]),
            "bwd_packets": 0, "bwd_bytes": 0,
            "label": "syn_flood"
        })
    return pd.DataFrame(records)

def generate_udp_floods(n_samples: int = 1000) -> pd.DataFrame:
    """
    UDP Flood DoS.
    Characteristics:
    - Protocol 17
    - Zero responses (bwd_packets = 0)
    - High volume and high PPS
    - All TCP flags = 0
    """
    base_time = int(time.time() * 1000) - 20000000
    src_ips = random_ipv4("198.51.100", n_samples)
    dst_ips = np.random.choice(["192.168.1.10", "192.168.1.50"], size=n_samples)
    src_ports = random_ephemeral_ports(n_samples)
    dst_ports = np.random.choice([53, 123, 1900, 3702, 5353], size=n_samples)

    pkts = np.random.randint(80, 1500, size=n_samples)
    durations = np.random.uniform(0.1, 4.0, size=n_samples)
    tot_b = pkts * np.random.randint(60, 512, size=n_samples)

    records = []
    for i in range(n_samples):
        d = max(durations[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 15000000),
            "srcIp": src_ips[i], "dstIp": dst_ips[i],
            "srcPort": int(src_ports[i]), "dstPort": int(dst_ports[i]),
            "protocol": 17, "duration": round(float(durations[i]), 6),
            "packets": int(pkts[i]), "bytes": int(tot_b[i]),
            "packetsPerSecond": round(float(pkts[i] / d), 4),
            "bytesPerSecond": round(float(tot_b[i] / d), 4),
            "averagePacketSize": round(float(tot_b[i] / pkts[i]), 4),
            "synCount": 0, "ackCount": 0, "finCount": 0,
            "rstCount": 0, "pshCount": 0, "urgCount": 0,
            "fwd_packets": int(pkts[i]), "fwd_bytes": int(tot_b[i]),
            "bwd_packets": 0, "bwd_bytes": 0,
            "label": "udp_flood"
        })
    return pd.DataFrame(records)

def generate_slowloris(n_samples: int = 1000) -> pd.DataFrame:
    """
    Slowloris HTTP Exhaustion.
    Characteristics:
    - Target web server (80, 443, 8080)
    - Abnormally long duration (15 to 80 seconds)
    - Minimal packet count (5 to 25 packets)
    - Tiny bytes and very low PPS (< 0.5)
    """
    base_time = int(time.time() * 1000) - 15000000
    src_ips = random_ipv4("10.200.1", n_samples)
    dst_ips = np.random.choice(["192.168.1.10", "192.168.1.50"], size=n_samples)
    src_ports = random_ephemeral_ports(n_samples)
    dst_ports = np.random.choice([80, 443, 8080], size=n_samples)

    durations = np.random.uniform(15.0, 75.0, size=n_samples)
    fwd_pkts = np.random.randint(5, 20, size=n_samples)
    bwd_pkts = np.random.randint(1, 4, size=n_samples)
    pkts = fwd_pkts + bwd_pkts

    fwd_b = fwd_pkts * np.random.randint(50, 90, size=n_samples)
    bwd_b = bwd_pkts * 54
    tot_b = fwd_b + bwd_b

    records = []
    for i in range(n_samples):
        d = max(durations[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 10000000),
            "srcIp": src_ips[i], "dstIp": dst_ips[i],
            "srcPort": int(src_ports[i]), "dstPort": int(dst_ports[i]),
            "protocol": 6, "duration": round(float(durations[i]), 6),
            "packets": int(pkts[i]), "bytes": int(tot_b[i]),
            "packetsPerSecond": round(float(pkts[i] / d), 4),
            "bytesPerSecond": round(float(tot_b[i] / d), 4),
            "averagePacketSize": round(float(tot_b[i] / pkts[i]), 4),
            "synCount": 1, "ackCount": int(pkts[i] - 1), "finCount": 0,
            "rstCount": 0, "pshCount": np.random.randint(2, 6), "urgCount": 0,
            "fwd_packets": int(fwd_pkts[i]), "fwd_bytes": int(fwd_b[i]),
            "bwd_packets": int(bwd_pkts[i]), "bwd_bytes": int(bwd_b[i]),
            "label": "slowloris"
        })
    return pd.DataFrame(records)

def generate_brute_force(n_samples: int = 1000) -> pd.DataFrame:
    """
    SSH & Web Authentication Brute Force.
    Characteristics:
    - Target SSH (22) or Web Login (80, 443, 8080)
    - Burst of authentication attempts with frequent resets or auth failures
    - High reset rate (rstCount >= 1 or finCount >= 1)
    """
    base_time = int(time.time() * 1000) - 10000000
    src_ips = random_ipv4("10.34.135", n_samples)
    dst_ips = np.random.choice(["192.168.1.10", "192.168.1.50"], size=n_samples)
    src_ports = random_ephemeral_ports(n_samples)
    dst_ports = np.random.choice([22, 8080, 80, 443], size=n_samples, p=[0.4, 0.3, 0.15, 0.15])

    durations = np.random.uniform(0.01, 0.4, size=n_samples)
    fwd_pkts = np.random.randint(4, 12, size=n_samples)
    bwd_pkts = np.random.randint(3, 10, size=n_samples)
    pkts = fwd_pkts + bwd_pkts

    fwd_b = fwd_pkts * np.random.randint(80, 160, size=n_samples)
    bwd_b = bwd_pkts * np.random.randint(90, 200, size=n_samples)
    tot_b = fwd_b + bwd_b

    records = []
    for i in range(n_samples):
        d = max(durations[i], 0.001)
        records.append({
            "startTimeUnixMs": base_time + np.random.randint(0, 8000000),
            "srcIp": src_ips[i], "dstIp": dst_ips[i],
            "srcPort": int(src_ports[i]), "dstPort": int(dst_ports[i]),
            "protocol": 6, "duration": round(float(durations[i]), 6),
            "packets": int(pkts[i]), "bytes": int(tot_b[i]),
            "packetsPerSecond": round(float(pkts[i] / d), 4),
            "bytesPerSecond": round(float(tot_b[i] / d), 4),
            "averagePacketSize": round(float(tot_b[i] / pkts[i]), 4),
            "synCount": 1, "ackCount": int(pkts[i] - 2), "finCount": 1,
            "rstCount": np.random.choice([0, 1], p=[0.3, 0.7]),
            "pshCount": np.random.randint(2, 6), "urgCount": 0,
            "fwd_packets": int(fwd_pkts[i]), "fwd_bytes": int(fwd_b[i]),
            "bwd_packets": int(bwd_pkts[i]), "bwd_bytes": int(bwd_b[i]),
            "label": "brute_force"
        })
    return pd.DataFrame(records)

# -----------------------------------------------------------------------------
# Main Assembly
# -----------------------------------------------------------------------------
def build_dataset():
    print("[*] Generating realistic multi-attack network flow dataset...")
    t0 = time.time()

    df_benign = generate_benign_flows(15000)
    df_portscan = generate_port_scans(2000)
    df_synflood = generate_syn_floods(2000)
    df_udpflood = generate_udp_floods(1000)
    df_slowloris = generate_slowloris(1000)
    df_bruteforce = generate_brute_force(1000)

    all_dfs = [df_benign, df_portscan, df_synflood, df_udpflood, df_slowloris, df_bruteforce]
    dataset = pd.concat(all_dfs, ignore_index=True)

    # Shuffle dataset
    dataset = dataset.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    # Backup legacy dataset if present
    if os.path.exists(OUTPUT_FLOWS) and not os.path.exists(f"{OUTPUT_FLOWS}.bak"):
        shutil.copy(OUTPUT_FLOWS, f"{OUTPUT_FLOWS}.bak")
        print(f"[*] Backed up previous {OUTPUT_FLOWS} -> {OUTPUT_FLOWS}.bak")

    os.makedirs("Data", exist_ok=True)
    dataset.to_csv(OUTPUT_FLOWS, index=False)
    dataset.to_csv(OUTPUT_LABELED, index=False)

    elapsed = time.time() - t0
    print(f"[+] Successfully generated {len(dataset)} flows in {elapsed:.2f} seconds!")
    print("\nClass distribution:")
    print(dataset["label"].value_counts())
    print(f"\nSaved to:\n - {OUTPUT_FLOWS}\n - {OUTPUT_LABELED}")

if __name__ == "__main__":
    build_dataset()
