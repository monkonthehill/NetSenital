#!/usr/bin/env python3
"""
web_app.py - NetSentinel Web Dashboard & Control Center

Features:
- Web GUI to enumerate interfaces and start/stop NetSentinel capture.
- Real-time WebSocket streaming of live traffic, throughput, and flow stats.
- Automated ML threat scoring with XGBoost & Random Forest.
- Interactive charts (Throughput, TCP Flags, Protocol distribution, Threats).
"""

import asyncio
import os
import signal
import subprocess
import sys
import time
from typing import Dict, List, Optional
import warnings

# Use orjson when available — it is ~3-5x faster than stdlib json for our payload shapes.
# Falls back to stdlib json transparently so the app works without it installed.
try:
    import orjson as _orjson
    def _json_dumps(obj: dict) -> str:
        return _orjson.dumps(obj).decode("utf-8")
except ImportError:
    import json as _json_fallback
    def _json_dumps(obj: dict) -> str:  # type: ignore[misc]
        return _json_fallback.dumps(obj, separators=(",", ":"))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import joblib
import numpy as np
import pandas as pd
import uvicorn
import xgboost as xgb

app = FastAPI(title="NetSentinel Control Dashboard")

# Global process tracking
SNIFFER_PROCESS: Optional[subprocess.Popen] = None
SNIFFER_INTERFACE: str = ""
ML_MODEL_TYPE: str = "xgb"
ML_THRESHOLD: float = 0.6
CLIENTS: List[WebSocket] = []

# Uptime tracking — set when capture starts
CAPTURE_START_TIME: Optional[float] = None

# Aggregate stats for /api/stats hydration endpoint
TOTAL_FLOWS: int = 0
TOTAL_ATTACKS: int = 0

# Load ML model
MODEL = None
MODEL_BOOSTER = None
FEATURE_COLS = [
    "srcPort", "dstPort", "protocol",
    "duration", "packets", "bytes", "packetsPerSecond", "bytesPerSecond",
    "averagePacketSize", "synCount", "ackCount", "finCount", "rstCount", "pshCount", "urgCount",
    "fwd_packets", "fwd_bytes", "bwd_packets", "bwd_bytes"
]

def load_ml_model(model_type="xgb"):
    global MODEL, MODEL_BOOSTER, ML_MODEL_TYPE
    ML_MODEL_TYPE = model_type
    try:
        if model_type == "xgb" and os.path.exists("models/xgb_model.json"):
            MODEL = xgb.XGBClassifier()
            MODEL.load_model("models/xgb_model.json")
            MODEL_BOOSTER = MODEL.get_booster()
            # Warm up OpenMP thread pools & JIT with dummy inference
            dummy = np.zeros((1, 19), dtype=np.float32)
            MODEL_BOOSTER.inplace_predict(dummy)
            print("[ML] Loaded & warmed up XGBoost model (inplace_predict active)")
        elif model_type == "rf" and os.path.exists("models/rf_model.joblib"):
            MODEL = joblib.load("models/rf_model.joblib")
            MODEL_BOOSTER = None
            dummy = np.zeros((1, 19), dtype=np.float32)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                MODEL.predict_proba(dummy)
            print("[ML] Loaded & warmed up Random Forest model")
        else:
            MODEL = None
            MODEL_BOOSTER = None
            print("[ML] Model file not found, running heuristic/mock")
    except Exception as e:
        print(f"[ML] Error loading model: {e}")
        MODEL = None
        MODEL_BOOSTER = None

load_ml_model("xgb")

import ctypes

# Cache interface list — querying libpcap via ctypes is relatively expensive;
# interfaces virtually never change at runtime, so cache for 30 seconds.
_IFACE_CACHE: List[str] = []
_IFACE_CACHE_TS: float = 0.0
_IFACE_CACHE_TTL: float = 30.0

def get_interfaces() -> List[str]:
    global _IFACE_CACHE, _IFACE_CACHE_TS
    now = time.monotonic()
    if _IFACE_CACHE and (now - _IFACE_CACHE_TS) < _IFACE_CACHE_TTL:
        return _IFACE_CACHE  # serve from cache — no libpcap overhead

    interfaces = []
    try:
        pcap = ctypes.CDLL("libpcap.so.1")
        class PcapIf(ctypes.Structure):
            pass
        PcapIf._fields_ = [
            ("next", ctypes.POINTER(PcapIf)),
            ("name", ctypes.c_char_p),
            ("description", ctypes.c_char_p),
            ("addresses", ctypes.c_void_p),
            ("flags", ctypes.c_uint)
        ]
        alldevs = ctypes.POINTER(PcapIf)()
        errbuf = ctypes.create_string_buffer(256)
        if pcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf) == 0:
            curr = alldevs
            while curr:
                if curr.contents.name:
                    interfaces.append(curr.contents.name.decode("utf-8", errors="ignore"))
                curr = curr.contents.next
            pcap.pcap_freealldevs(alldevs)
    except Exception:
        pass

    if not interfaces:
        interfaces = ["lo", "enp230s0f1u1", "wlp229s0"]

    # Update cache
    _IFACE_CACHE = interfaces
    _IFACE_CACHE_TS = now
    return interfaces

LAST_ERROR: str = ""

@app.get("/api/status")
def get_status():
    global LAST_ERROR
    is_running = SNIFFER_PROCESS is not None and SNIFFER_PROCESS.poll() is None
    return {
        "running": is_running,
        "interface": SNIFFER_INTERFACE,
        "model": ML_MODEL_TYPE,
        "threshold": ML_THRESHOLD,
        "interfaces": get_interfaces(),
        "error": LAST_ERROR
    }

@app.get("/api/stats")
def get_stats():
    """Aggregate stats endpoint for initial page hydration and polling fallback."""
    is_running = SNIFFER_PROCESS is not None and SNIFFER_PROCESS.poll() is None
    uptime = int(time.time() - CAPTURE_START_TIME) if CAPTURE_START_TIME and is_running else 0
    return {
        "total_flows": TOTAL_FLOWS,
        "total_attacks": TOTAL_ATTACKS,
        "uptime_seconds": uptime,
        "running": is_running,
        "model": ML_MODEL_TYPE,
        "threshold": ML_THRESHOLD,
    }

@app.post("/api/start")
def start_capture(interface: str = "lo", model: str = "xgb", threshold: float = 0.6):
    global SNIFFER_PROCESS, SNIFFER_INTERFACE, ML_THRESHOLD, LAST_ERROR
    global CAPTURE_START_TIME, TOTAL_FLOWS, TOTAL_ATTACKS
    LAST_ERROR = ""
    if SNIFFER_PROCESS and SNIFFER_PROCESS.poll() is None:
        return {"status": "already_running"}

    load_ml_model(model)
    ML_THRESHOLD = threshold
    SNIFFER_INTERFACE = interface

    # Make sure binary is compiled
    if not os.path.exists("netsentinel"):
        subprocess.run([
            "g++", "-O2", "-Wall", "-Wextra", "-Wshadow",
            "src/main.cpp", "src/sniffer.cpp", "src/parser.cpp", "src/flow.cpp", "src/extractor.cpp",
            "-o", "netsentinel", "-lpcap"
        ], check=True)

    # Spawn process with pipes to check for initial startup errors
    SNIFFER_PROCESS = subprocess.Popen(
        ["./netsentinel", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )

    # Give it a moment to check if it immediately failed due to permissions or interface errors
    time.sleep(0.4)
    if SNIFFER_PROCESS.poll() is not None:
        stderr_output = SNIFFER_PROCESS.stderr.read()
        SNIFFER_PROCESS = None
        if "permission" in stderr_output.lower() or "cap_net_raw" in stderr_output.lower():
            LAST_ERROR = "Permission denied: Packet capture requires root privileges. Run: 'sudo setcap cap_net_raw=ep ./netsentinel' or run the dashboard with sudo."
        else:
            LAST_ERROR = stderr_output.strip() or "Process exited unexpectedly."
        return {"status": "error", "message": LAST_ERROR}

    # Reset session stats and record start time
    CAPTURE_START_TIME = time.time()
    TOTAL_FLOWS = 0
    TOTAL_ATTACKS = 0

    return {"status": "started", "interface": interface}

@app.post("/api/stop")
def stop_capture():
    global SNIFFER_PROCESS, CAPTURE_START_TIME
    if SNIFFER_PROCESS and SNIFFER_PROCESS.poll() is None:
        SNIFFER_PROCESS.send_signal(signal.SIGINT)
        try:
            SNIFFER_PROCESS.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            SNIFFER_PROCESS.kill()
        SNIFFER_PROCESS = None
        CAPTURE_START_TIME = None
        return {"status": "stopped"}
    return {"status": "not_running"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    CLIENTS.append(websocket)
    try:
        while True:
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        CLIENTS.remove(websocket)

async def broadcast_telemetry():
    """Background task reading newly added flows from Data/packet_data.csv and broadcasting live metrics."""
    global TOTAL_FLOWS, TOTAL_ATTACKS
    last_file_pos = 0
    csv_path = "Data/packet_data.csv"

    if os.path.exists(csv_path):
        last_file_pos = os.path.getsize(csv_path)

    last_heartbeat = 0.0

    while True:
        await asyncio.sleep(0.05)  # 50ms polling for sub-frame responsiveness
        if not CLIENTS:
            continue

        new_flows = []
        if os.path.exists(csv_path):
            current_size = os.path.getsize(csv_path)
            if current_size > last_file_pos:
                with open(csv_path, "r") as f:
                    f.seek(last_file_pos)
                    lines = f.readlines()
                    last_file_pos = f.tell()

                parsed_flows = []
                feature_matrix = []

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("startTimeUnixMs"):
                        continue
                    parts = line.split(",")
                    if len(parts) >= 18:
                        try:
                            # Contiguous slice from parts[3:18] (15 flow metrics)
                            f_vec = [float(p) for p in parts[3:18]]
                            if len(parts) >= 22:
                                f_vec.extend([float(p) for p in parts[18:22]])
                            else:
                                f_vec.extend([f_vec[4], f_vec[5], 0.0, 0.0])  # fwd pkts, fwd bytes, 0, 0

                            flow = {
                                "startTimeUnixMs": float(parts[0]),
                                "srcIp": parts[1],
                                "dstIp": parts[2],
                                "srcPort": int(f_vec[0]),
                                "dstPort": int(f_vec[1]),
                                "protocol": int(f_vec[2]),
                                "duration": f_vec[3],
                                "packets": int(f_vec[4]),
                                "bytes": int(f_vec[5]),
                                "packetsPerSecond": f_vec[6],
                                "bytesPerSecond": f_vec[7],
                                "averagePacketSize": f_vec[8],
                                "synCount": int(f_vec[9]),
                                "ackCount": int(f_vec[10]),
                                "finCount": int(f_vec[11]),
                                "rstCount": int(f_vec[12]),
                                "pshCount": int(f_vec[13]),
                                "urgCount": int(f_vec[14]),
                                "fwd_packets": int(f_vec[15]),
                                "fwd_bytes": int(f_vec[16]),
                                "bwd_packets": int(f_vec[17]),
                                "bwd_bytes": int(f_vec[18]),
                            }
                            feature_matrix.append(f_vec)
                            parsed_flows.append(flow)
                        except Exception:
                            pass

                # Ultra-fast vectorized batch ML scoring (< 1ms per 100 flows via inplace_predict)
                if parsed_flows:
                    if feature_matrix:
                        X_batch = np.array(feature_matrix, dtype=np.float32)
                        if MODEL_BOOSTER is not None:
                            # Direct C++ booster evaluation bypassing DMatrix allocation
                            scores = MODEL_BOOSTER.inplace_predict(X_batch)
                        elif MODEL is not None:
                            with warnings.catch_warnings():
                                warnings.simplefilter("ignore")
                                scores = MODEL.predict_proba(X_batch)[:, 1]
                        else:
                            scores = np.zeros(len(parsed_flows), dtype=np.float32)

                        for idx, f in enumerate(parsed_flows):
                            score = float(scores[idx])
                            f["threat_score"] = score
                            f["is_anomaly"] = score >= ML_THRESHOLD
                    else:
                        for f in parsed_flows:
                            f["threat_score"] = 0.0
                            f["is_anomaly"] = False

                    # Update aggregate session counters
                    batch_attacks = sum(1 for f in parsed_flows if f["is_anomaly"])
                    TOTAL_FLOWS += len(parsed_flows)
                    TOTAL_ATTACKS += batch_attacks

                    new_flows.extend(parsed_flows)

        now = time.time()
        # Adaptive heartbeat: skip sending empty frames if less than 1.0s elapsed since last broadcast
        if not new_flows and (now - last_heartbeat) < 1.0:
            continue
        last_heartbeat = now

        is_running = SNIFFER_PROCESS is not None and SNIFFER_PROCESS.poll() is None
        uptime = int(now - CAPTURE_START_TIME) if CAPTURE_START_TIME and is_running else 0
        payload = {
            "type": "telemetry",
            "running": is_running,
            "timestamp": now,
            "uptime": uptime,
            "new_flows": new_flows
        }

        # High-performance serialization via orjson (or json fallback) done ONCE per broadcast
        payload_str = _json_dumps(payload)

        # Broadcast to all connected clients
        for ws in list(CLIENTS):
            try:
                await ws.send_text(payload_str)
            except Exception:
                if ws in CLIENTS:
                    CLIENTS.remove(ws)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcast_telemetry())

@app.get("/", response_class=HTMLResponse)
def index_page():
    return HTML_CONTENT

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel | Cyber Command & Threat Analytics</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        /* ─────────────────────────────────────────
           CSS Variables & Reset
        ───────────────────────────────────────── */
        :root {
            --bg-dark:        #080c14;
            --bg-darker:      #050810;
            --panel-bg:       #0d1424;
            --panel-bg2:      #101828;
            --panel-border:   #1a2540;
            --panel-glow:     rgba(0, 229, 255, 0.06);
            --accent-blue:    #00e5ff;
            --accent-blue2:   #38bdf8;
            --accent-red:     #ff1744;
            --accent-red2:    #ff6b6b;
            --accent-green:   #00e676;
            --accent-yellow:  #ffd740;
            --accent-purple:  #b388ff;
            --accent-orange:  #ff9100;
            --text-light:     #e2e8f0;
            --text-muted:     #64748b;
            --text-dim:       #334155;
            --radius:         10px;
            --radius-sm:      6px;
            --transition:     0.2s ease;
        }

        *, *::before, *::after {
            box-sizing: border-box; margin: 0; padding: 0;
        }
        html { scroll-behavior: smooth; }
        body {
            background: var(--bg-dark);
            color: var(--text-light);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "JetBrains Mono", monospace;
            min-height: 100vh;
            /* Subtle scanline grid overlay */
            background-image:
                linear-gradient(rgba(0,229,255,0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,229,255,0.015) 1px, transparent 1px);
            background-size: 40px 40px;
        }

        /* ─────────────────────────────────────────
           Scrollbar
        ───────────────────────────────────────── */
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: var(--bg-darker); }
        ::-webkit-scrollbar-thumb { background: var(--panel-border); border-radius: 99px; }

        /* ─────────────────────────────────────────
           Layout Wrapper
        ───────────────────────────────────────── */
        .app-wrapper {
            max-width: 1600px;
            margin: 0 auto;
            padding: 1.25rem 1.5rem 2rem;
        }

        /* ─────────────────────────────────────────
           Header
        ───────────────────────────────────────── */
        header {
            position: sticky; top: 0; z-index: 100;
            display: flex; justify-content: space-between; align-items: center;
            padding: 0.9rem 1.25rem;
            background: rgba(8, 12, 20, 0.92);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--panel-border);
            border-radius: 0 0 var(--radius) var(--radius);
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 24px rgba(0,0,0,0.4);
        }

        .logo {
            display: flex; align-items: center; gap: 10px;
            font-size: 1.35rem; font-weight: 800; letter-spacing: 1.5px;
            color: var(--accent-blue);
            text-shadow: 0 0 20px rgba(0,229,255,0.5);
        }
        .logo-icon {
            font-size: 1.6rem;
            animation: pulse-icon 3s ease-in-out infinite;
        }
        @keyframes pulse-icon {
            0%, 100% { filter: drop-shadow(0 0 6px rgba(0,229,255,0.6)); transform: scale(1); }
            50%       { filter: drop-shadow(0 0 16px rgba(0,229,255,0.9)); transform: scale(1.08); }
        }
        .logo-sub {
            font-size: 0.7rem; color: var(--text-muted);
            font-weight: 400; letter-spacing: 2px; text-transform: uppercase;
        }

        .header-right {
            display: flex; align-items: center; gap: 1rem;
        }

        .github-btn {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 5px 12px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--panel-border);
            border-radius: var(--radius-sm);
            color: var(--text-light);
            text-decoration: none;
            font-size: 0.8rem;
            font-weight: 600;
            transition: all var(--transition);
        }
        .github-btn:hover {
            background: rgba(0, 229, 255, 0.12);
            border-color: var(--accent-blue);
            color: var(--accent-blue);
            box-shadow: 0 0 12px rgba(0, 229, 255, 0.3);
            transform: translateY(-1px);
        }
        .github-btn svg { fill: currentColor; }

        /* Capture timer */
        #captureTimer {
            font-family: "JetBrains Mono", monospace;
            font-size: 0.85rem; color: var(--text-muted);
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            padding: 5px 12px; border-radius: 99px;
            transition: var(--transition);
        }
        #captureTimer.active {
            color: var(--accent-green);
            border-color: rgba(0,230,118,0.3);
            background: rgba(0,230,118,0.06);
            text-shadow: 0 0 8px rgba(0,230,118,0.5);
        }

        /* Status badge */
        .status-badge {
            display: flex; align-items: center; gap: 7px;
            padding: 6px 14px; border-radius: 99px;
            font-size: 0.8rem; font-weight: 700; letter-spacing: 1px;
            background: var(--panel-bg); color: var(--text-muted);
            border: 1px solid var(--panel-border);
            transition: var(--transition);
        }
        .status-badge .dot {
            width: 7px; height: 7px; border-radius: 50%;
            background: var(--text-dim);
            transition: var(--transition);
        }
        .status-badge.active {
            background: rgba(0,230,118,0.08);
            color: var(--accent-green);
            border-color: rgba(0,230,118,0.3);
            box-shadow: 0 0 12px rgba(0,230,118,0.15);
        }
        .status-badge.active .dot {
            background: var(--accent-green);
            box-shadow: 0 0 6px var(--accent-green);
            animation: blink-dot 1.2s ease-in-out infinite;
        }
        @keyframes blink-dot {
            0%, 100% { opacity: 1; }
            50%       { opacity: 0.3; }
        }

        /* ─────────────────────────────────────────
           Toast Notification
        ───────────────────────────────────────── */
        #toast {
            position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 9999;
            background: #1a0a0f; border: 1px solid var(--accent-red);
            color: var(--accent-red2); border-radius: var(--radius);
            padding: 1rem 1.25rem; max-width: 420px;
            font-size: 0.88rem; line-height: 1.5;
            box-shadow: 0 8px 32px rgba(255,23,68,0.3);
            transform: translateY(120%);
            transition: transform 0.35s cubic-bezier(.22,.68,0,1.2);
        }
        #toast.show { transform: translateY(0); }
        #toast strong { display: block; margin-bottom: 4px; font-size: 0.95rem; }

        /* ─────────────────────────────────────────
           Control Panel
        ───────────────────────────────────────── */
        .control-panel {
            display: grid;
            grid-template-columns: 1fr 1fr 220px 100px 100px;
            gap: 1rem;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            padding: 1.1rem 1.25rem;
            border-radius: var(--radius);
            margin-bottom: 1.5rem;
            align-items: end;
            box-shadow: 0 2px 20px rgba(0,0,0,0.3), inset 0 0 40px var(--panel-glow);
        }

        .form-group { display: flex; flex-direction: column; gap: 5px; }
        .form-group label {
            font-size: 0.72rem; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 1px; font-weight: 600;
        }
        .input-wrap { position: relative; display: flex; align-items: center; }
        .input-wrap .input-icon {
            position: absolute; right: 8px;
            font-size: 0.9rem; pointer-events: none; opacity: 0.5;
        }

        select, input[type="number"], input[type="range"] {
            width: 100%; padding: 8px 10px;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--panel-border);
            color: var(--text-light);
            border-radius: var(--radius-sm);
            outline: none;
            font-size: 0.88rem;
            transition: var(--transition);
            appearance: none;
        }
        select:hover, input[type="number"]:hover { border-color: rgba(0,229,255,0.3); }
        select:focus, input[type="number"]:focus {
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 2px rgba(0,229,255,0.12);
        }
        select { cursor: pointer; }

        /* Threshold slider */
        .threshold-wrap { display: flex; flex-direction: column; gap: 5px; }
        .threshold-row { display: flex; align-items: center; gap: 8px; }
        .threshold-label {
            font-size: 0.88rem; font-weight: 700;
            color: var(--accent-blue); min-width: 36px;
        }
        input[type="range"] {
            padding: 0; height: 4px;
            background: var(--panel-border);
            border: none; cursor: pointer; border-radius: 99px;
            accent-color: var(--accent-blue);
        }

        /* Buttons */
        .btn {
            width: 100%; padding: 9px 12px;
            font-weight: 700; font-size: 0.88rem; letter-spacing: 0.5px;
            border-radius: var(--radius-sm); border: none; cursor: pointer;
            transition: all var(--transition);
            height: 38px; display: flex; align-items: center; justify-content: center; gap: 5px;
        }
        .btn:active { transform: scale(0.97); }
        .btn-start {
            background: linear-gradient(135deg, #00c853, #00e676);
            color: #0a1a0f;
            box-shadow: 0 2px 12px rgba(0,230,118,0.3);
        }
        .btn-start:hover { box-shadow: 0 4px 20px rgba(0,230,118,0.5); filter: brightness(1.1); }
        .btn-stop {
            background: linear-gradient(135deg, #c62828, #ff1744);
            color: white;
            box-shadow: 0 2px 12px rgba(255,23,68,0.3);
        }
        .btn-stop:hover { box-shadow: 0 4px 20px rgba(255,23,68,0.5); filter: brightness(1.1); }
        .btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }

        /* ─────────────────────────────────────────
           KPI Stats Bar
        ───────────────────────────────────────── */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 1rem; margin-bottom: 1.5rem;
        }
        .stat-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            padding: 1.1rem 1.2rem;
            border-radius: var(--radius);
            position: relative; overflow: hidden;
            transition: border-color var(--transition), box-shadow var(--transition);
        }
        .stat-card::before {
            content: ''; position: absolute; inset: 0;
            background: linear-gradient(135deg, var(--card-accent, rgba(0,229,255,0.04)), transparent 60%);
            pointer-events: none;
        }
        .stat-card:hover {
            border-color: rgba(0,229,255,0.3);
            box-shadow: 0 4px 20px rgba(0,229,255,0.08);
        }
        .stat-card.danger:hover {
            border-color: rgba(255,23,68,0.3);
            box-shadow: 0 4px 20px rgba(255,23,68,0.08);
        }

        .stat-label {
            font-size: 0.72rem; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 1px; font-weight: 600;
        }
        .stat-value {
            font-size: 1.7rem; font-weight: 800; margin-top: 6px;
            color: var(--text-light); font-variant-numeric: tabular-nums;
            transition: color var(--transition);
        }
        .stat-footer {
            font-size: 0.72rem; color: var(--text-muted);
            margin-top: 4px; display: flex; align-items: center; gap: 4px;
        }
        .stat-trend { font-weight: 700; }
        .stat-trend.up   { color: var(--accent-red); }
        .stat-trend.down { color: var(--accent-green); }
        .stat-trend.flat { color: var(--text-muted); }

        /* Sparkline canvas inside stat card */
        .sparkline {
            position: absolute; bottom: 0; right: 0;
            width: 80px; height: 40px; opacity: 0.4;
        }

        /* ─────────────────────────────────────────
           Dashboard Charts Grid
        ───────────────────────────────────────── */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.25rem; margin-bottom: 1.25rem;
        }
        .chart-row {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 1.25rem; margin-bottom: 1.25rem;
        }
        .panel {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: var(--radius);
            padding: 1.1rem 1.25rem;
            box-shadow: inset 0 0 30px var(--panel-glow);
        }
        .panel-header {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 1rem;
        }
        .panel-title {
            font-size: 0.88rem; font-weight: 700;
            color: var(--accent-blue); text-transform: uppercase; letter-spacing: 0.5px;
            display: flex; align-items: center; gap: 7px;
        }
        .panel-badge {
            font-size: 0.72rem; padding: 2px 8px; border-radius: 99px;
            background: rgba(0,229,255,0.1); color: var(--accent-blue);
            font-weight: 600;
        }
        .panel-badge.red {
            background: rgba(255,23,68,0.12); color: var(--accent-red);
        }

        /* ─────────────────────────────────────────
           Alerts Panel
        ───────────────────────────────────────── */
        #alerts-container {
            max-height: 280px; overflow-y: auto;
            display: flex; flex-direction: column; gap: 6px;
        }
        .alerts-empty {
            color: var(--text-muted); font-size: 0.85rem;
            text-align: center; padding: 2rem 0;
            display: flex; flex-direction: column; align-items: center; gap: 8px;
        }
        .alerts-empty span { font-size: 2rem; opacity: 0.4; }

        .alert-item {
            background: rgba(255, 23, 68, 0.07);
            border-left: 3px solid var(--accent-red);
            padding: 8px 10px; border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
            font-size: 0.82rem; display: flex; flex-direction: column; gap: 3px;
            animation: slide-in 0.25s ease forwards;
        }
        @keyframes slide-in {
            from { opacity: 0; transform: translateX(-10px); }
            to   { opacity: 1; transform: translateX(0); }
        }
        .alert-item.severity-critical { border-color: #ff1744; }
        .alert-item.severity-high     { border-color: #ff6b6b; background: rgba(255,107,107,0.07); }
        .alert-item.severity-medium   { border-color: #ffd740; background: rgba(255,215,64,0.07); }
        .alert-header { display: flex; align-items: center; justify-content: space-between; }
        .alert-src { color: var(--text-muted); font-size: 0.78rem; }
        .alert-score { font-weight: 800; }
        .severity-badge {
            font-size: 0.68rem; font-weight: 800; padding: 1px 6px;
            border-radius: 3px; letter-spacing: 0.5px;
        }
        .severity-badge.critical { background: rgba(255,23,68,0.2); color: #ff1744; }
        .severity-badge.high     { background: rgba(255,107,107,0.2); color: #ff6b6b; }
        .severity-badge.medium   { background: rgba(255,215,64,0.15); color: #ffd740; }

        .clear-btn {
            font-size: 0.72rem; padding: 3px 10px; border-radius: 99px;
            background: rgba(255,23,68,0.1); color: var(--accent-red);
            border: 1px solid rgba(255,23,68,0.2); cursor: pointer;
            transition: var(--transition); font-weight: 600;
        }
        .clear-btn:hover { background: rgba(255,23,68,0.2); }

        /* ─────────────────────────────────────────
           Flow Table
        ───────────────────────────────────────── */
        .table-panel {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: var(--radius);
            overflow: hidden;
            margin-bottom: 1.5rem;
        }
        .table-panel-header {
            display: flex; align-items: center; justify-content: space-between;
            padding: 0.9rem 1.25rem;
            border-bottom: 1px solid var(--panel-border);
            background: var(--panel-bg2);
        }

        .table-wrap { overflow-x: auto; max-height: 420px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.83rem; text-align: left; }
        thead {
            position: sticky; top: 0; z-index: 5;
            background: var(--panel-bg2);
        }
        th {
            padding: 9px 12px; color: var(--text-muted);
            font-weight: 600; text-transform: uppercase; font-size: 0.72rem;
            letter-spacing: 0.5px; white-space: nowrap; cursor: pointer;
            user-select: none; border-bottom: 1px solid var(--panel-border);
            transition: color var(--transition);
        }
        th:hover { color: var(--accent-blue); }
        th .sort-arrow { opacity: 0.4; margin-left: 3px; font-size: 0.65rem; }
        th.sorted .sort-arrow { opacity: 1; color: var(--accent-blue); }

        td {
            padding: 8px 12px; border-bottom: 1px solid rgba(26,37,64,0.6);
            vertical-align: middle; white-space: nowrap;
        }
        tbody tr { transition: background var(--transition); }
        tbody tr:hover { background: rgba(255,255,255,0.03); }
        tbody tr.flash-attack {
            animation: flash-red 0.6s ease forwards;
        }
        @keyframes flash-red {
            0%   { background: rgba(255,23,68,0.25); }
            100% { background: transparent; }
        }

        /* Protocol badge pills */
        .proto-badge {
            display: inline-block; padding: 2px 7px; border-radius: 4px;
            font-size: 0.72rem; font-weight: 700; letter-spacing: 0.5px;
        }
        .proto-tcp  { background: rgba(0,229,255,0.12); color: var(--accent-blue); }
        .proto-udp  { background: rgba(255,215,64,0.12); color: var(--accent-yellow); }
        .proto-icmp { background: rgba(179,136,255,0.12); color: var(--accent-purple); }

        /* Verdict badges */
        .badge {
            display: inline-block; padding: 2px 8px;
            border-radius: 4px; font-size: 0.72rem; font-weight: 700;
        }
        .badge-attack {
            background: rgba(255,23,68,0.15); color: var(--accent-red);
            border: 1px solid rgba(255,23,68,0.3);
        }
        .badge-benign {
            background: rgba(0,230,118,0.1); color: var(--accent-green);
        }

        /* Threat score mini bar */
        .score-bar-wrap {
            display: flex; align-items: center; gap: 7px;
        }
        .score-bar {
            height: 4px; border-radius: 99px; flex: 1; min-width: 50px;
            background: rgba(255,255,255,0.07);
            position: relative; overflow: hidden;
        }
        .score-bar-fill {
            height: 100%; border-radius: 99px;
            transition: width 0.3s ease;
        }
        .score-text { font-size: 0.82rem; font-variant-numeric: tabular-nums; min-width: 36px; }

        /* ─────────────────────────────────────────
           Footer
        ───────────────────────────────────────── */
        footer {
            text-align: center; padding-top: 1.5rem;
            font-size: 0.75rem; color: var(--text-dim);
            border-top: 1px solid var(--panel-border);
        }
        footer a { color: var(--text-muted); text-decoration: none; }
        footer a:hover { color: var(--accent-blue); }

        /* ─────────────────────────────────────────
           Responsive
        ───────────────────────────────────────── */
        @media (max-width: 1200px) {
            .stats-grid { grid-template-columns: repeat(3, 1fr); }
            .control-panel { grid-template-columns: 1fr 1fr; }
            .chart-row { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .dashboard-grid { grid-template-columns: 1fr; }
            .chart-row { grid-template-columns: 1fr; }
            .control-panel { grid-template-columns: 1fr; }
            .logo-sub { display: none; }
        }
    </style>
</head>
<body>
<div class="app-wrapper">

    <!-- ── Header ── -->
    <header>
        <div class="logo">
            <span class="logo-icon">🛡️</span>
            <div>
                NetSentinel
                <div class="logo-sub">Cyber Command & ML-NIDS</div>
            </div>
        </div>
        <div class="header-right">
            <a href="https://github.com/monkonthehill/NetSenital" target="_blank" class="github-btn" title="View Source on GitHub">
                <svg width="15" height="15" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                GitHub
            </a>
            <div id="captureTimer">⏱ 00:00:00</div>
            <div id="statusBadge" class="status-badge">
                <span class="dot"></span>
                <span id="statusText">CAPTURE IDLE</span>
            </div>
        </div>
    </header>

    <!-- ── Control Panel ── -->
    <div class="control-panel">
        <div class="form-group">
            <label>Network Interface</label>
            <div class="input-wrap">
                <select id="ifaceSelect"><option>Loading…</option></select>
                <span class="input-icon">🔌</span>
            </div>
        </div>
        <div class="form-group">
            <label>ML Detection Model</label>
            <div class="input-wrap">
                <select id="modelSelect">
                    <option value="xgb" selected>XGBoost (19-Feature)</option>
                    <option value="rf">Random Forest</option>
                </select>
                <span class="input-icon">🤖</span>
            </div>
        </div>
        <div class="threshold-wrap">
            <label style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;font-weight:600;">
                Anomaly Threshold
            </label>
            <div class="threshold-row">
                <input type="range" id="thresholdSlider" min="0.10" max="0.99" step="0.01" value="0.60"
                       oninput="document.getElementById('thresholdVal').innerText=parseFloat(this.value).toFixed(2)">
                <span class="threshold-label" id="thresholdVal">0.60</span>
            </div>
        </div>
        <button class="btn btn-start" id="startBtn" onclick="startCapture()">▶ START</button>
        <button class="btn btn-stop"  id="stopBtn"  onclick="stopCapture()">■ STOP</button>
    </div>

    <!-- ── KPI Stats Bar ── -->
    <div class="stats-grid">
        <div class="stat-card" style="--card-accent: rgba(0,229,255,0.05);">
            <div class="stat-label">Total Flows</div>
            <div class="stat-value" id="valTotalFlows">0</div>
            <div class="stat-footer"><span class="stat-trend flat" id="trendFlows">— session</span></div>
            <canvas class="sparkline" id="spkFlows"></canvas>
        </div>
        <div class="stat-card" style="--card-accent: rgba(0,229,255,0.05);">
            <div class="stat-label">Live Throughput</div>
            <div class="stat-value" id="valThroughput">0 KB/s</div>
            <div class="stat-footer"><span class="stat-trend flat" id="trendBps">— bps</span></div>
            <canvas class="sparkline" id="spkBps"></canvas>
        </div>
        <div class="stat-card danger" style="--card-accent: rgba(255,23,68,0.04);">
            <div class="stat-label">Attacks Detected</div>
            <div class="stat-value" id="valAttacks" style="color:var(--accent-red);">0</div>
            <div class="stat-footer"><span class="stat-trend flat" id="trendAttacks">— this session</span></div>
            <canvas class="sparkline" id="spkAttacks"></canvas>
        </div>
        <div class="stat-card danger" style="--card-accent: rgba(255,23,68,0.04);">
            <div class="stat-label">Attack Rate</div>
            <div class="stat-value" id="valAttackRate">0.0%</div>
            <div class="stat-footer">of total flows</div>
        </div>
        <div class="stat-card" style="--card-accent: rgba(179,136,255,0.04);">
            <div class="stat-label">Avg Packet Size</div>
            <div class="stat-value" id="valAvgPkt">0 B</div>
            <div class="stat-footer">bytes per packet</div>
        </div>
        <div class="stat-card" style="--card-accent: rgba(255,145,0,0.04);">
            <div class="stat-label">Packets / sec</div>
            <div class="stat-value" id="valPps">0</div>
            <div class="stat-footer">live PPS rate</div>
        </div>
    </div>

    <!-- ── Main Dashboard: Throughput Chart + Alerts ── -->
    <div class="dashboard-grid">
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">📈 Live Throughput &amp; PPS</div>
                <span class="panel-badge" id="chartPointsBadge">60 pts</span>
            </div>
            <canvas id="trafficChart" height="120"></canvas>
        </div>
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">🚨 Security Alerts <span class="panel-badge red" id="alertCountBadge">0</span></div>
                <button class="clear-btn" onclick="clearAlerts()">Clear</button>
            </div>
            <div id="alerts-container">
                <div class="alerts-empty">
                    <span>🔵</span>
                    No active threat alerts
                </div>
            </div>
        </div>
    </div>

    <!-- ── Secondary Chart Row ── -->
    <div class="chart-row">
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">🥧 Protocol Distribution</div>
            </div>
            <canvas id="protoChart" height="160"></canvas>
        </div>
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">🚩 TCP Flag Counts</div>
            </div>
            <canvas id="flagsChart" height="160"></canvas>
        </div>
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">⚡ Threat Score Timeline</div>
            </div>
            <canvas id="threatChart" height="160"></canvas>
        </div>
    </div>

    <!-- ── Live Flow Table ── -->
    <div class="table-panel">
        <div class="table-panel-header">
            <div class="panel-title">📋 Live Flow Stream &amp; Directional Telemetry</div>
            <span class="panel-badge">Real-time ML Scoring Active</span>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th onclick="sortTable('src')">Source <span class="sort-arrow">↕</span></th>
                        <th onclick="sortTable('dst')">Destination <span class="sort-arrow">↕</span></th>
                        <th>Proto</th>
                        <th onclick="sortTable('packets')">Packets (Fwd/Bwd) <span class="sort-arrow">↕</span></th>
                        <th onclick="sortTable('bytes')">Bytes <span class="sort-arrow">↕</span></th>
                        <th>Duration</th>
                        <th onclick="sortTable('bps')">Throughput <span class="sort-arrow">↕</span></th>
                        <th onclick="sortTable('score')">Threat Score <span class="sort-arrow sort-arrow" id="sortScoreArrow">↓</span></th>
                        <th>Verdict</th>
                    </tr>
                </thead>
                <tbody id="flowTableBody">
                    <tr>
                        <td colspan="9" style="text-align:center;color:var(--text-muted);padding:2rem;">
                            Start capture to view active flow analytics…
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <footer>
        NetSentinel NIDS &nbsp;·&nbsp; ML-Powered Threat Analytics &nbsp;·&nbsp;
        <a href="https://github.com/monkonthehill/NetSenital" target="_blank">github.com/monkonthehill/NetSenital</a>
    </footer>
</div>

<!-- ── Toast ── -->
<div id="toast"></div>

<script>
/* ═══════════════════════════════════════════════════
   State
═══════════════════════════════════════════════════ */
let totalFlows   = 0;
let totalAttacks = 0;
let alertCount   = 0;
let flowList     = [];  // rolling window of last 100 flows

// Rolling 60-point data windows for the throughput chart
const CHART_WINDOW = 60;
let bpsWindow  = Array(CHART_WINDOW).fill(0);
let ppsWindow  = Array(CHART_WINDOW).fill(0);

// Sparkline rolling windows (20 pts)
let spkFlowsData   = Array(20).fill(0);
let spkBpsData     = Array(20).fill(0);
let spkAttackData  = Array(20).fill(0);

// Protocol & Flag accumulators
let protoCounts = { TCP: 0, UDP: 0, ICMP: 0 };
let flagCounts  = { SYN: 0, ACK: 0, FIN: 0, RST: 0, PSH: 0, URG: 0 };

// Threat timeline scatter points (max 200)
let threatPoints = [];

// Table sort state
let sortKey = 'score';
let sortAsc = false;

// Capture timer
let captureInterval = null;
let captureStartTs  = null;

// Batching flag — chart & table update at most once per 500ms
let pendingUpdate = false;

/* ═══════════════════════════════════════════════════
   Chart.js Initialisation
═══════════════════════════════════════════════════ */
// ── Throughput / PPS chart (smooth tension & active animation) ──
const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctxTraffic, {
    type: 'line',
    data: {
        labels: Array(CHART_WINDOW).fill(''),
        datasets: [
            {
                label: 'KB/s',
                borderColor: '#00e5ff',
                backgroundColor: 'rgba(0,229,255,0.08)',
                data: bpsWindow,
                tension: 0.25, fill: true,
                pointRadius: 0, borderWidth: 2
            },
            {
                label: 'PPS',
                borderColor: '#ffd740',
                data: ppsWindow,
                tension: 0.25, yAxisID: 'y1',
                pointRadius: 0, borderWidth: 1.5
            }
        ]
    },
    options: {
        responsive: true,
        animation: { duration: 300, easing: 'easeOutQuad' },
        interaction: { mode: 'index', intersect: false },
        scales: {
            x: { display: false },
            y:  { grid: { color: '#1a2540' }, ticks: { color: '#64748b', font: { size: 11 } } },
            y1: { position: 'right', grid: { display: false }, ticks: { color: '#ffd740', font: { size: 11 } } }
        },
        plugins: {
            legend: { labels: { color: '#94a3b8', font: { size: 12 } } }
        }
    }
});

// ── Protocol Distribution doughnut (animated transitions) ──
const ctxProto = document.getElementById('protoChart').getContext('2d');
const protoChart = new Chart(ctxProto, {
    type: 'doughnut',
    data: {
        labels: ['TCP', 'UDP', 'ICMP'],
        datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['rgba(0,229,255,0.7)', 'rgba(255,215,64,0.7)', 'rgba(179,136,255,0.7)'],
            borderColor:      ['#00e5ff', '#ffd740', '#b388ff'],
            borderWidth: 1.5, hoverOffset: 6
        }]
    },
    options: {
        responsive: true,
        animation: { duration: 450, animateRotate: true, animateScale: true, easing: 'easeOutCirc' },
        cutout: '65%',
        plugins: {
            legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 }, padding: 10 } }
        }
    }
});

// ── TCP Flags bar chart (animated transition) ──
const ctxFlags = document.getElementById('flagsChart').getContext('2d');
const flagsChart = new Chart(ctxFlags, {
    type: 'bar',
    data: {
        labels: ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'],
        datasets: [{
            label: 'Flag Count',
            data: [0, 0, 0, 0, 0, 0],
            backgroundColor: [
                'rgba(0,230,118,0.6)', 'rgba(0,229,255,0.6)', 'rgba(255,215,64,0.6)',
                'rgba(255,23,68,0.6)', 'rgba(179,136,255,0.6)', 'rgba(255,145,0,0.6)'
            ],
            borderColor: [
                '#00e676', '#00e5ff', '#ffd740', '#ff1744', '#b388ff', '#ff9100'
            ],
            borderWidth: 1, borderRadius: 4
        }]
    },
    options: {
        responsive: true,
        animation: { duration: 350, easing: 'easeOutQuart' },
        scales: {
            x: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { display: false } },
            y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1a2540' } }
        },
        plugins: { legend: { display: false } }
    }
});

// ── Threat Score Timeline scatter ──
const ctxThreat = document.getElementById('threatChart').getContext('2d');
const threatChart = new Chart(ctxThreat, {
    type: 'scatter',
    data: {
        datasets: [
            {
                label: 'Benign',
                data: [],
                backgroundColor: 'rgba(0,230,118,0.5)',
                pointRadius: 3, pointHoverRadius: 5
            },
            {
                label: 'Attack',
                data: [],
                backgroundColor: 'rgba(255,23,68,0.7)',
                pointRadius: 4, pointHoverRadius: 6
            }
        ]
    },
    options: {
        responsive: true, animation: false,
        scales: {
            x: { display: false },
            y: {
                min: 0, max: 1,
                ticks: { color: '#64748b', font: { size: 10 } },
                grid: { color: '#1a2540' }
            }
        },
        plugins: {
            legend: { labels: { color: '#94a3b8', font: { size: 11 } } },
            annotation: {}  // threshold line rendered manually below
        }
    }
});

/* ═══════════════════════════════════════════════════
   Sparklines (lightweight canvas, no Chart.js)
═══════════════════════════════════════════════════ */
function drawSparkline(canvasId, data, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const max = Math.max(...data, 1);
    const step = W / (data.length - 1);
    ctx.beginPath();
    data.forEach((v, i) => {
        const x = i * step;
        const y = H - (v / max) * H * 0.85;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();
}

/* ═══════════════════════════════════════════════════
   Status & Initialisation
═══════════════════════════════════════════════════ */
async function fetchStatus() {
    try {
        const res  = await fetch('/api/status');
        const data = await res.json();
        const sel  = document.getElementById('ifaceSelect');
        sel.innerHTML = '';
        data.interfaces.forEach(iface => {
            const opt = document.createElement('option');
            opt.value = iface; opt.innerText = iface;
            sel.appendChild(opt);
        });
        // Restore threshold display
        document.getElementById('thresholdSlider').value = data.threshold;
        document.getElementById('thresholdVal').innerText = data.threshold.toFixed(2);
        updateRunningUI(data.running);
    } catch (e) {
        console.warn('fetchStatus failed:', e);
    }
}

function updateRunningUI(running) {
    const badge = document.getElementById('statusBadge');
    const text  = document.getElementById('statusText');
    const timer = document.getElementById('captureTimer');
    if (running) {
        badge.classList.add('active');
        text.innerText = 'LIVE CAPTURE';
        timer.classList.add('active');
    } else {
        badge.classList.remove('active');
        text.innerText = 'CAPTURE IDLE';
        timer.classList.remove('active');
        stopCaptureTimer();
    }
}

/* ═══════════════════════════════════════════════════
   Capture Controls
═══════════════════════════════════════════════════ */
async function startCapture() {
    const iface     = document.getElementById('ifaceSelect').value;
    const model     = document.getElementById('modelSelect').value;
    const threshold = parseFloat(document.getElementById('thresholdSlider').value);

    document.getElementById('startBtn').disabled = true;
    try {
        const res  = await fetch(`/api/start?interface=${iface}&model=${model}&threshold=${threshold}`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'error') {
            showToast('Capture Error', data.message);
            updateRunningUI(false);
        } else {
            updateRunningUI(true);
            startCaptureTimer();
            // Reset session stats
            totalFlows = 0; totalAttacks = 0; alertCount = 0;
            flowList = []; protoCounts = { TCP:0, UDP:0, ICMP:0 };
            flagCounts = { SYN:0, ACK:0, FIN:0, RST:0, PSH:0, URG:0 };
            threatPoints = [];
            document.getElementById('alerts-container').innerHTML =
                '<div class="alerts-empty"><span>🔵</span>No active threat alerts</div>';
            document.getElementById('alertCountBadge').innerText = '0';
            updateKPIs(0, 0, 0, 0, 0, 0);
        }
    } catch (e) {
        showToast('Network Error', String(e));
    } finally {
        document.getElementById('startBtn').disabled = false;
    }
}

async function stopCapture() {
    await fetch('/api/stop', { method: 'POST' });
    updateRunningUI(false);
}

/* ═══════════════════════════════════════════════════
   Capture Timer
═══════════════════════════════════════════════════ */
function startCaptureTimer() {
    captureStartTs = Date.now();
    stopCaptureTimer();
    captureInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - captureStartTs) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        document.getElementById('captureTimer').innerText = `⏱ ${h}:${m}:${s}`;
    }, 1000);
}
function stopCaptureTimer() {
    if (captureInterval) { clearInterval(captureInterval); captureInterval = null; }
    document.getElementById('captureTimer').innerText = '⏱ 00:00:00';
}

/* ═══════════════════════════════════════════════════
   Toast Notification (replaces browser alert)
═══════════════════════════════════════════════════ */
let toastTimeout = null;
function showToast(title, message) {
    const t = document.getElementById('toast');
    t.innerHTML = `<strong>⚠ ${title}</strong>${message}`;
    t.classList.add('show');
    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => t.classList.remove('show'), 6000);
}

/* ═══════════════════════════════════════════════════
   WebSocket
═══════════════════════════════════════════════════ */
const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
let ws;

function connectWS() {
    ws = new WebSocket(`${wsProto}//${window.location.host}/ws`);
    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'telemetry') {
                updateRunningUI(data.running);
                if (data.running && !captureInterval) startCaptureTimer();
                if (data.new_flows && data.new_flows.length > 0) {
                    ingestFlows(data.new_flows);
                }
            }
        } catch (e) {
            console.error('WS parse error:', e);
        }
    };
    ws.onclose = () => setTimeout(connectWS, 2000);  // auto-reconnect
    ws.onerror = () => ws.close();
}
connectWS();

/* ═══════════════════════════════════════════════════
   Flow Ingestion (hot path)
═══════════════════════════════════════════════════ */
function ingestFlows(flows) {
    let sumBps = 0, sumPps = 0, sumPktSize = 0, batchAttacks = 0;
    const tNow = Date.now() / 1000;

    for (let i = 0; i < flows.length; i++) {
        const f = flows[i];
        sumBps     += f.bytesPerSecond;
        sumPps     += f.packetsPerSecond;
        sumPktSize += f.averagePacketSize || 0;

        // Protocol count
        if (f.protocol === 6)       protoCounts.TCP++;
        else if (f.protocol === 17) protoCounts.UDP++;
        else                        protoCounts.ICMP++;

        // TCP flags accumulate
        flagCounts.SYN += f.synCount || 0;
        flagCounts.ACK += f.ackCount || 0;
        flagCounts.FIN += f.finCount || 0;
        flagCounts.RST += f.rstCount || 0;
        flagCounts.PSH += f.pshCount || 0;
        flagCounts.URG += f.urgCount || 0;

        // Threat timeline (capped to 100 points for super-speed rendering)
        threatPoints.push({ x: tNow, y: f.threat_score, attack: f.is_anomaly });
        if (threatPoints.length > 100) threatPoints.shift();

        if (f.is_anomaly) {
            batchAttacks++;
            addAlert(f);
        }
        flowList.unshift(f);
    }

    // Keep flow list bounded to 100
    if (flowList.length > 100) flowList.length = 100;

    totalFlows   += flows.length;
    totalAttacks += batchAttacks;

    const kbps = sumBps / 1024;
    updateKPIs(totalFlows, kbps, totalAttacks, sumPps, sumPktSize / flows.length, batchAttacks);

    // Rolling throughput window
    bpsWindow.shift(); bpsWindow.push(kbps);
    ppsWindow.shift(); ppsWindow.push(sumPps);

    // Sparkline data
    spkFlowsData.shift();  spkFlowsData.push(flows.length);
    spkBpsData.shift();    spkBpsData.push(kbps);
    spkAttackData.shift(); spkAttackData.push(batchAttacks);

    // Batch DOM updates with requestAnimationFrame (aligned with 60 FPS refresh)
    if (!pendingUpdate) {
        pendingUpdate = true;
        requestAnimationFrame(() => {
            flushChartUpdates();
            renderTable();
            pendingUpdate = false;
        });
    }
}

/* ═══════════════════════════════════════════════════
   KPI Update
═══════════════════════════════════════════════════ */
function updateKPIs(flows, kbps, attacks, pps, avgPkt, batchAttacks) {
    document.getElementById('valTotalFlows').innerText  = flows.toLocaleString();
    document.getElementById('valThroughput').innerText  = kbps.toFixed(1) + ' KB/s';
    document.getElementById('valAttacks').innerText     = attacks.toLocaleString();
    document.getElementById('valPps').innerText         = pps.toFixed(0);
    document.getElementById('valAvgPkt').innerText      = isNaN(avgPkt) ? '0 B' : avgPkt.toFixed(0) + ' B';
    const rate = flows > 0 ? ((attacks / flows) * 100).toFixed(1) : '0.0';
    document.getElementById('valAttackRate').innerText  = rate + '%';

    // Trend indicators
    const trendA = document.getElementById('trendAttacks');
    if (batchAttacks > 0) { trendA.innerText = `▲ +${batchAttacks} new`; trendA.className = 'stat-trend up'; }
    else { trendA.innerText = '✓ clean batch'; trendA.className = 'stat-trend flat'; }
}

/* ═══════════════════════════════════════════════════
   Chart Flush (smooth animated dataset updates)
═══════════════════════════════════════════════════ */
function flushChartUpdates() {
    // Throughput
    trafficChart.update();

    // Protocol donut
    const pd = protoChart.data.datasets[0].data;
    pd[0] = protoCounts.TCP;
    pd[1] = protoCounts.UDP;
    pd[2] = protoCounts.ICMP;
    protoChart.update();

    // Flags
    const fd = flagsChart.data.datasets[0].data;
    fd[0] = flagCounts.SYN;
    fd[1] = flagCounts.ACK;
    fd[2] = flagCounts.FIN;
    fd[3] = flagCounts.RST;
    fd[4] = flagCounts.PSH;
    fd[5] = flagCounts.URG;
    flagsChart.update();

    // Threat scatter
    const benign = [];
    const attack = [];
    for (let i = 0; i < threatPoints.length; i++) {
        const p = threatPoints[i];
        if (p.attack) attack.push({ x: p.x, y: p.y });
        else benign.push({ x: p.x, y: p.y });
    }
    threatChart.data.datasets[0].data = benign;
    threatChart.data.datasets[1].data = attack;
    threatChart.update();

    // Sparklines
    drawSparkline('spkFlows',   spkFlowsData,  '#00e5ff');
    drawSparkline('spkBps',     spkBpsData,    '#00e5ff');
    drawSparkline('spkAttacks', spkAttackData, '#ff1744');
}

/* ═══════════════════════════════════════════════════
   Alerts Panel
═══════════════════════════════════════════════════ */
function getSeverity(score) {
    if (score >= 0.90) return 'critical';
    if (score >= 0.70) return 'high';
    return 'medium';
}

function addAlert(f) {
    const container = document.getElementById('alerts-container');
    // Clear the empty placeholder on first alert
    const emptyEl = container.querySelector('.alerts-empty');
    if (emptyEl) container.innerHTML = '';

    const sev       = getSeverity(f.threat_score);
    const scoreText = (f.threat_score * 100).toFixed(1) + '%';
    const target    = f.dstPort == 80 ? 'HTTP' : f.dstPort == 443 ? 'HTTPS' : f.dstPort == 22 ? 'SSH' : 'Port ' + f.dstPort;

    const item = document.createElement('div');
    item.className = `alert-item severity-${sev}`;
    item.innerHTML = `
        <div class="alert-header">
            <strong>[ALERT] ${target} &mdash; ${f.srcIp} &rarr; ${f.dstIp}</strong>
            <span class="severity-badge ${sev}">${sev.toUpperCase()}</span>
        </div>
        <div class="alert-src">
            <span style="color:var(--accent-red);font-weight:700;">Score: ${scoreText}</span>
            &nbsp;·&nbsp; Proto: ${f.protocol === 6 ? 'TCP' : f.protocol === 17 ? 'UDP' : 'ICMP'}
        </div>
    `;
    container.prepend(item);
    if (container.children.length > 25) container.removeChild(container.lastChild);

    alertCount++;
    document.getElementById('alertCountBadge').innerText = alertCount;
}

function clearAlerts() {
    document.getElementById('alerts-container').innerHTML =
        '<div class="alerts-empty"><span>🔵</span>No active threat alerts</div>';
    alertCount = 0;
    document.getElementById('alertCountBadge').innerText = '0';
}

/* ═══════════════════════════════════════════════════
   Flow Table — DOM Row Pooling (60 FPS Zero Allocations)
═══════════════════════════════════════════════════ */
const POOL_SIZE = 25;
const tableRows = [];
let tbodyEl = null;
let emptyRowEl = null;

function initTableRowPool() {
    tbodyEl = document.getElementById('flowTableBody');
    tbodyEl.innerHTML = '';

    emptyRowEl = document.createElement('tr');
    emptyRowEl.id = 'emptyTableRow';
    emptyRowEl.innerHTML = '<td colspan="9" style="text-align:center;color:var(--text-muted);padding:2rem;">Start capture to view active flow analytics…</td>';
    tbodyEl.appendChild(emptyRowEl);

    for (let i = 0; i < POOL_SIZE; i++) {
        const tr = document.createElement('tr');
        tr.style.display = 'none';
        for (let c = 0; c < 9; c++) {
            tr.appendChild(document.createElement('td'));
        }
        tbodyEl.appendChild(tr);
        tableRows.push(tr);
    }
}

function sortTable(key) {
    if (sortKey === key) { sortAsc = !sortAsc; }
    else { sortKey = key; sortAsc = false; }
    // Update header arrows
    document.querySelectorAll('th .sort-arrow').forEach(a => a.style.color = '');
    renderTable();
}

function renderTable() {
    if (!tbodyEl) return;
    if (flowList.length === 0) {
        if (emptyRowEl) emptyRowEl.style.display = '';
        for (let i = 0; i < POOL_SIZE; i++) {
            tableRows[i].style.display = 'none';
        }
        return;
    }
    if (emptyRowEl) emptyRowEl.style.display = 'none';

    let sortedFlows = flowList;
    if (sortKey) {
        const dir = sortAsc ? 1 : -1;
        const getVal = (f, k) => {
            switch (k) {
                case 'src':     return f.srcIp;
                case 'dst':     return f.dstIp;
                case 'packets': return f.packets;
                case 'bytes':   return f.bytes;
                case 'bps':     return f.bytesPerSecond;
                case 'score':   return f.threat_score;
                default:        return 0;
            }
        };
        sortedFlows = [...flowList].sort((a, b) => {
            const va = getVal(a, sortKey), vb = getVal(b, sortKey);
            if (va < vb) return -1 * dir;
            if (va > vb) return  1 * dir;
            return 0;
        });
    }

    const count = Math.min(sortedFlows.length, POOL_SIZE);
    for (let idx = 0; idx < count; idx++) {
        const f = sortedFlows[idx];
        const tr = tableRows[idx];
        tr.style.display = '';

        const isRecentAttack = (idx < 3 && f.is_anomaly);
        tr.className = isRecentAttack ? 'flash-attack' : '';

        const cells = tr.cells;
        cells[0].textContent = `${f.srcIp}:${f.srcPort}`;
        cells[1].textContent = `${f.dstIp}:${f.dstPort}`;

        if (f.protocol === 6) {
            cells[2].innerHTML = '<span class="proto-badge proto-tcp">TCP</span>';
        } else if (f.protocol === 17) {
            cells[2].innerHTML = '<span class="proto-badge proto-udp">UDP</span>';
        } else {
            cells[2].innerHTML = '<span class="proto-badge proto-icmp">ICMP</span>';
        }

        cells[3].textContent = `${f.packets} (${f.fwd_packets} / ${f.bwd_packets})`;
        cells[4].textContent = `${f.bytes.toLocaleString()} B`;
        cells[5].textContent = `${f.duration.toFixed(3)}s`;
        cells[6].textContent = `${(f.bytesPerSecond / 1024).toFixed(1)} KB/s`;

        const scorePct = (f.threat_score * 100).toFixed(1);
        const barColor = f.is_anomaly ? '#ff1744' : '#00e676';
        cells[7].innerHTML = `<div class="score-bar-wrap"><div class="score-bar"><div class="score-bar-fill" style="width:${scorePct}%;background:${barColor};"></div></div><span class="score-text" style="color:${barColor};">${scorePct}%</span></div>`;

        cells[8].innerHTML = f.is_anomaly ? '<span class="badge badge-attack">ATTACK</span>' : '<span class="badge badge-benign">BENIGN</span>';
    }

    for (let idx = count; idx < POOL_SIZE; idx++) {
        tableRows[idx].style.display = 'none';
    }
}

/* ═══════════════════════════════════════════════════
   Boot
═══════════════════════════════════════════════════ */
initTableRowPool();
fetchStatus();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    # If not running as root, re-execute the script using sudo so packet capture always works
    if os.geteuid() != 0:
        print("[NetSentinel] Elevating privileges with sudo for raw packet capture...")
        try:
            # os.execvp replaces the current process with sudo python3 web_app.py ...
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"[NetSentinel] Could not elevate with sudo: {e}")
            print("[NetSentinel] Continuing as unprivileged user...")

    uvicorn.run(app, host="0.0.0.0", port=8000)
