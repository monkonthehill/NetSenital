#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import ctypes
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Set, Tuple
try:
    from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse
    import joblib
    import numpy as np
    import uvicorn
except ImportError as exc:
    print(f"\n[NetSentinel] Missing required Python package: {exc.name}", file=sys.stderr)
    print(f"[NetSentinel] Current Python binary: {sys.executable}", file=sys.stderr)
    if os.geteuid() == 0 and "SUDO_USER" in os.environ:
        print(
            "\n[Tip] You executed 'sudo python3 web_app.py', which uses the system root Python (/usr/bin/python3).\n"
            "Instead, run as your normal user — web_app.py automatically elevates with sudo while preserving your Python environment:\n"
            "   make run    or    python3 web_app.py",
            file=sys.stderr,
        )
    else:
        print(
            "\nPlease install the required dependencies in your active Python environment:\n"
            "   pip install -r requirements.txt",
            file=sys.stderr,
        )
    sys.exit(1)

# ── Fast JSON ───────────────────────────────────────────────────────────
try:
    import orjson as _orjson

    def _json_dumps(obj) -> str:
        return _orjson.dumps(obj).decode("utf-8")

except ImportError:
    import json as _json_fallback

    def _json_dumps(obj) -> str:
        return _json_fallback.dumps(obj, separators=(",", ":"))


# ── XGBoost (optional — RF-only deployments work without it) ────────────
try:
    import xgboost as xgb  # type: ignore
except ImportError:
    xgb = None  # type: ignore


# ═══════════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════════
HOST = os.environ.get("NS_HOST", "127.0.0.1").strip()
PORT = int(os.environ.get("NS_PORT", "8000"))
API_TOKEN = os.environ.get("NS_TOKEN", "").strip()
CSV_PATH = os.environ.get("NS_CSV", "Data/packet_data.csv")
MODELS_DIR = Path(os.environ.get("NS_MODELS", "models"))
BIN_PATH = os.environ.get("NS_BIN", "./netsentinel")

FEATURE_COLS = [
    "srcPort",
    "dstPort",
    "protocol",
    "duration",
    "packets",
    "bytes",
    "packetsPerSecond",
    "bytesPerSecond",
    "averagePacketSize",
    "synCount",
    "ackCount",
    "finCount",
    "rstCount",
    "pshCount",
    "urgCount",
    "fwd_packets",
    "fwd_bytes",
    "bwd_packets",
    "bwd_bytes",
]


# ═══════════════════════════════════════════════════════════════════════
#  Shared state (thread-safe)
# ═══════════════════════════════════════════════════════════════════════
class _State:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.proc: Optional[subprocess.Popen] = None
        self.interface = ""
        self.model_type = "xgb"
        self.threshold = 0.60
        self.clients: Set[WebSocket] = set()
        self.start_time: Optional[float] = None
        self.total_flows = 0
        self.total_attacks = 0
        self.last_error = ""
        self.bg_task: Optional[asyncio.Task] = None

    def is_running(self) -> bool:
        with self.lock:
            return self.proc is not None and self.proc.poll() is None

    def snapshot(self) -> dict:
        with self.lock:
            running = self.proc is not None and self.proc.poll() is None
            uptime = (
                int(time.time() - self.start_time)
                if (self.start_time and running)
                else 0
            )
            return {
                "running": running,
                "interface": self.interface,
                "model": self.model_type,
                "threshold": self.threshold,
                "uptime": uptime,
                "total_flows": self.total_flows,
                "total_attacks": self.total_attacks,
                "error": self.last_error,
            }


state = _State()


# ═══════════════════════════════════════════════════════════════════════
#  Active Firewall & Threat Mitigation Engine (IPS Auto-Block)
# ═══════════════════════════════════════════════════════════════════════
class FirewallMitigationManager:
    """Manages active network mitigation and automated firewall block rules.

    Provides automated IP blocking for high-confidence threat actors with
    automatic cooldown unblocking, whitelist protection for loopback/management
    traffic, and genuine OS-level firewall rules (iptables/pfctl) where permitted.
    """

    def __init__(
        self,
        cooldown_sec: int = 60,
        threshold: float = 0.98,
        enabled: bool = True,
    ) -> None:
        self.lock = threading.RLock()
        self.enabled = enabled
        self.cooldown_sec = cooldown_sec
        self.threshold = threshold
        self.whitelist: Set[str] = {
            "127.0.0.1",
            "::1",
            "localhost",
            "0.0.0.0",
        }
        self.blocked: dict[str, dict] = {}

    def is_whitelisted(self, ip: str) -> bool:
        norm = str(ip).strip()
        return (
            norm in self.whitelist
            or norm.startswith("127.")
            or norm == "::1"
            or norm == "0.0.0.0"
        )

    def _apply_os_rule(self, ip: str) -> bool:
        """Apply genuine OS firewall drop if running with appropriate permissions."""
        if os.geteuid() != 0:
            return False
        try:
            if sys.platform == "darwin":
                return False
            else:
                chk = subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True,
                    timeout=1.0,
                )
                if chk.returncode != 0:
                    res = subprocess.run(
                        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True,
                        timeout=1.0,
                    )
                    return res.returncode == 0
                return True
        except Exception:
            return False

    def _remove_os_rule(self, ip: str) -> bool:
        """Remove OS firewall drop rule if present."""
        if os.geteuid() != 0:
            return False
        try:
            if sys.platform != "darwin":
                res = subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True,
                    timeout=1.0,
                )
                return res.returncode == 0
        except Exception:
            pass
        return False

    def reap_expired(self) -> List[str]:
        """Prune all expired IP blocks whose cooldown timer has elapsed."""
        now = time.time()
        with self.lock:
            expired = [
                ip
                for ip, data in self.blocked.items()
                if now >= data.get("unblock_at", 0)
            ]
            for ip in expired:
                data = self.blocked.pop(ip)
                if data.get("os_rule_applied"):
                    self._remove_os_rule(ip)
            return expired

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP address is actively blocked."""
        self.reap_expired()
        norm = str(ip).strip()
        with self.lock:
            return norm in self.blocked

    def block_ip(
        self,
        ip: str,
        reason: str = "Threat",
        threat_score: float = 1.0,
        duration_sec: Optional[int] = None,
    ) -> dict:
        """Block an offending IP address with an automatic unblock cooldown."""
        norm = str(ip).strip()
        self.reap_expired()
        with self.lock:
            dur = duration_sec if duration_sec is not None else self.cooldown_sec
            now = time.time()
            unblock_at = now + dur
            is_wl = self.is_whitelisted(norm)
            os_applied = False
            if not is_wl:
                os_applied = self._apply_os_rule(norm)

            entry = {
                "ip": norm,
                "reason": reason,
                "threat_score": float(threat_score),
                "blocked_at": now,
                "unblock_at": unblock_at,
                "duration_sec": dur,
                "is_whitelisted": is_wl,
                "os_rule_applied": os_applied,
            }
            self.blocked[norm] = entry
            return entry

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address immediately."""
        norm = str(ip).strip()
        with self.lock:
            if norm in self.blocked:
                data = self.blocked.pop(norm)
                if data.get("os_rule_applied"):
                    self._remove_os_rule(norm)
                return True
            return False

    def get_status(self) -> dict:
        """Get live mitigation status, active blocked IPs, and remaining cooldowns."""
        self.reap_expired()
        now = time.time()
        with self.lock:
            active_list = []
            for ip, data in sorted(
                self.blocked.items(), key=lambda kv: kv[1]["unblock_at"]
            ):
                rem = max(0, int(data["unblock_at"] - now))
                active_list.append(
                    {
                        "ip": ip,
                        "reason": data.get("reason", "Threat"),
                        "threat_score": data.get("threat_score", 1.0),
                        "remaining_sec": rem,
                        "duration_sec": data.get("duration_sec", self.cooldown_sec),
                        "blocked_at": data.get("blocked_at", now),
                        "unblock_at": data.get("unblock_at", now),
                        "is_whitelisted": data.get("is_whitelisted", False),
                        "os_rule_applied": data.get("os_rule_applied", False),
                    }
                )
            return {
                "enabled": self.enabled,
                "cooldown_sec": self.cooldown_sec,
                "threshold": self.threshold,
                "total_blocked": len(active_list),
                "blocked": active_list,
            }

    def configure(
        self,
        enabled: Optional[bool] = None,
        cooldown_sec: Optional[int] = None,
        threshold: Optional[float] = None,
    ) -> dict:
        """Update mitigation runtime configuration."""
        with self.lock:
            if enabled is not None:
                self.enabled = bool(enabled)
            if cooldown_sec is not None:
                self.cooldown_sec = max(5, int(cooldown_sec))
            if threshold is not None:
                self.threshold = max(0.50, min(1.0, float(threshold)))
            return self.get_status()


mitigation = FirewallMitigationManager()


# ═══════════════════════════════════════════════════════════════════════
#  ML model loading
# ═══════════════════════════════════════════════════════════════════════
MODEL: object = None
BOOSTER: object = None
CATEGORY_BOOSTER: object = None
ATTACK_CLASSES: dict[int, str] = {
    0: "Benign",
    1: "SYN Flood",
    2: "Port Scan",
    3: "Stealth Scan",
    4: "UDP Flood",
    5: "Slowloris",
    6: "Slow POST",
    7: "Brute Force",
    8: "ICMP Flood",
}


def load_ml_model(model_type: str) -> None:
    """Load (or reload) the ML model. Never raises — logs and falls back to mock."""
    global MODEL, BOOSTER, CATEGORY_BOOSTER, ATTACK_CLASSES
    state.model_type = model_type
    MODEL = BOOSTER = None

    # Load attack class mapping if available
    cat_json = MODELS_DIR / "attack_classes.json"
    if cat_json.exists():
        try:
            import json
            with open(cat_json) as f:
                raw_map = json.load(f)
                ATTACK_CLASSES = {int(k): str(v) for k, v in raw_map.items()}
        except Exception:
            pass

    # Load multiclass attack category classifier
    cat_path = MODELS_DIR / "category_model.json"
    if cat_path.exists() and xgb is not None:
        try:
            cm = xgb.XGBClassifier()
            cm.load_model(str(cat_path))
            cm.get_booster().inplace_predict(np.zeros((1, 19), dtype=np.float32))
            CATEGORY_BOOSTER = cm.get_booster()
            print(f"[ML] Attack Category Classifier loaded from {cat_path}")
        except Exception as exc:  # noqa: BLE001
            print(f"[ML] Category model load warning: {exc}")
            CATEGORY_BOOSTER = None

    try:
        if model_type == "xgb":
            path = MODELS_DIR / "xgb_model.json"
            if path.exists() and xgb is not None:
                m = xgb.XGBClassifier()
                m.load_model(str(path))
                m.get_booster().inplace_predict(np.zeros((1, 19), dtype=np.float32))
                MODEL, BOOSTER = m, m.get_booster()
                print(f"[ML] XGBoost loaded from {path} (inplace_predict warm)")
            else:
                print(f"[ML] XGBoost model missing at {path} — heuristic/mock mode")
        elif model_type == "rf":
            path = MODELS_DIR / "rf_model.joblib"
            if path.exists():
                m = joblib.load(str(path))
                import warnings

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    m.predict_proba(np.zeros((1, 19), dtype=np.float32))
                MODEL = m
                print(f"[ML] RandomForest loaded from {path}")
            else:
                print(f"[ML] RF model missing at {path} — heuristic/mock mode")
    except Exception as exc:  # noqa: BLE001
        print(f"[ML] Load failed: {exc} — heuristic/mock mode")
        MODEL = BOOSTER = None


load_ml_model("xgb")


# ═══════════════════════════════════════════════════════════════════════
#  Interface enumeration (cached, ctypes-typed)
# ═══════════════════════════════════════════════════════════════════════
class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]

_iface_cache: List[str] = []
_iface_cache_ts: float = 0.0
_IFACE_TTL = 30.0
_iface_lock = threading.Lock()


def get_interfaces() -> List[str]:
    global _iface_cache, _iface_cache_ts
    now = time.monotonic()
    with _iface_lock:
        if _iface_cache and (now - _iface_cache_ts) < _IFACE_TTL:
            return list(_iface_cache)

    found: List[str] = []
    try:
        import ctypes.util

        pcap_lib = ctypes.util.find_library("pcap")
        # Multi-platform candidate search paths (macOS dylib, Homebrew prefix, Linux so)
        candidates = [
            pcap_lib,
            "libpcap.dylib",
            "/usr/lib/libpcap.dylib",
            "/opt/homebrew/opt/libpcap/lib/libpcap.dylib",
            "/usr/local/opt/libpcap/lib/libpcap.dylib",
            "libpcap.so.1",
            "libpcap.so",
        ]
        pcap = None
        for candidate in candidates:
            if candidate:
                try:
                    pcap = ctypes.CDLL(candidate)
                    if pcap:
                        break
                except Exception:
                    pass

        if pcap is None:
            raise OSError("Could not locate or load libpcap shared library")

        pcap.pcap_findalldevs.argtypes = [
            ctypes.POINTER(ctypes.POINTER(_PcapIf)),
            ctypes.c_char_p,
        ]
        pcap.pcap_findalldevs.restype = ctypes.c_int
        pcap.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]

        alldevs = ctypes.POINTER(_PcapIf)()
        errbuf = ctypes.create_string_buffer(256)
        if pcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf) == 0:
            cur = alldevs
            while cur:
                if cur.contents.name:
                    found.append(cur.contents.name.decode("utf-8", "ignore"))
                cur = cur.contents.next
            pcap.pcap_freealldevs(alldevs)
    except Exception as exc:  # noqa: BLE001
        print(f"[Net] libpcap enumeration failed: {exc}")

    if not found:
        # Default loopback interface: lo0 on macOS, lo on Linux
        found = ["lo0" if sys.platform == "darwin" else "lo"]

    with _iface_lock:
        _iface_cache, _iface_cache_ts = found, now
    return list(found)


# ═══════════════════════════════════════════════════════════════════════
#  CSV tailer — truncation-safe, partial-line-safe, header-once
# ═══════════════════════════════════════════════════════════════════════
class FlowTailer:
    def __init__(self, path: str) -> None:
        self.path = path
        self.pos = 0
        self.header_done = False
        self._prime()

    def _prime(self) -> None:
        try:
            if os.path.exists(self.path):
                self.pos = os.path.getsize(self.path)
                self.header_done = self.pos > 0
        except OSError:
            self.pos = 0

    def reset(self) -> None:
        self.pos = 0
        self.header_done = False

    def read_new_lines(self) -> List[str]:
        if not os.path.exists(self.path):
            return []
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []

        if size < self.pos:
            self.reset()
        if size == self.pos:
            return []

        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.pos)
                data = fh.read()
        except OSError:
            return []

        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            return []
        complete = data[: last_nl + 1]
        self.pos += len(complete)

        text = complete.decode("utf-8", "ignore")
        lines = text.splitlines()

        if not self.header_done and lines and lines[0].startswith("startTimeUnixMs"):
            lines = lines[1:]
        self.header_done = True
        return lines


def heuristic_attack_category(f: dict) -> str:
    """Fallback heuristic classifier if ML category booster is unavailable."""
    proto = f.get("protocol", 6)
    d_port = f.get("dstPort", 0)
    dur = f.get("duration", 0.0)
    pps = f.get("packetsPerSecond", 0.0)
    syn = f.get("synCount", 0)
    ack = f.get("ackCount", 0)
    fin = f.get("finCount", 0)
    rst = f.get("rstCount", 0)
    pkts = f.get("packets", 0)
    fwd_b = f.get("fwd_bytes", 0)
    bwd_pkts = f.get("bwd_packets", 0)

    if proto == 1:
        return "ICMP Flood"
    if proto == 17:
        return "UDP Flood"
    if fin > 0 and ack == 0:
        return "Stealth Scan"
    # Slowloris: low packets per second over multi-second duration
    if dur >= 5.0 and pps <= 2.5:
        return "Slowloris"
    # SYN flood: embryonic connection or high SYN with low payload bytes
    if (syn >= 1 and pkts <= 5 and fwd_b < 150 and d_port in (80, 443, 8080, 8888, 8889, 8000, 9999)) or (syn >= 3 and ack == 0 and bwd_pkts == 0):
        return "SYN Flood"
    # Brute Force: credential attempts on auth ports or repeated reset handshakes with payload
    if d_port in (22, 21, 3389) or (rst >= 1 and fwd_b > 200):
        return "Brute Force"
    if pkts <= 2 and bwd_pkts <= 1:
        return "Port Scan"
    return "Attack"


# ═══════════════════════════════════════════════════════════════════════
#  Parsing + scoring (runs in a worker thread)
# ═══════════════════════════════════════════════════════════════════════
def _parse_and_score(lines: List[str], threshold: float) -> Tuple[List[dict], int]:
    parsed: List[dict] = []
    feature_matrix: List[List[float]] = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("startTimeUnixMs"):
            continue
        parts = line.split(",")
        if len(parts) < 18:
            continue
        try:
            f_vec = [float(p) for p in parts[3:18]]
            if len(parts) >= 22:
                f_vec.extend(float(p) for p in parts[18:22])
            else:
                f_vec.extend([f_vec[4], f_vec[5], 0.0, 0.0])

            parsed.append(
                {
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
            )
            feature_matrix.append(f_vec)
        except (ValueError, IndexError):
            continue

    if not parsed:
        return [], 0

    X = np.asarray(feature_matrix, dtype=np.float32)
    if BOOSTER is not None:
        scores = BOOSTER.inplace_predict(X)
    elif MODEL is not None:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            scores = MODEL.predict_proba(X)[:, 1]  # type: ignore[attr-defined]
    else:
        scores = np.zeros(len(parsed), dtype=np.float32)

    cat_probs = None
    if CATEGORY_BOOSTER is not None:
        try:
            cat_probs = CATEGORY_BOOSTER.inplace_predict(X)
        except Exception:
            cat_probs = None

    attacks = 0
    for i, f in enumerate(parsed):
        s = float(scores[i])
        f["threat_score"] = s
        f["is_anomaly"] = s >= threshold
        if f["is_anomaly"]:
            attacks += 1
            if cat_probs is not None:
                cid = int(np.argmax(cat_probs[i]))
                if cid == 0:
                    cid = int(np.argmax(cat_probs[i, 1:])) + 1
                f["attack_type"] = ATTACK_CLASSES.get(cid, "Attack")
            else:
                f["attack_type"] = heuristic_attack_category(f)

            # Active Mitigation: auto-block high certainty threats (>= threshold, default 0.98)
            if mitigation.enabled and s >= mitigation.threshold:
                mitigation.block_ip(
                    f["srcIp"],
                    reason=f.get("attack_type", "Threat"),
                    threat_score=s,
                )
        else:
            f["attack_type"] = "Benign"

        f["is_blocked"] = mitigation.is_blocked(f["srcIp"])

    return parsed, attacks


# ═══════════════════════════════════════════════════════════════════════
#  FastAPI app
# ═══════════════════════════════════════════════════════════════════════
app = FastAPI(title="NetSentinel Control Dashboard")


def _check_token(request: Request) -> None:
    if not API_TOKEN:
        return
    auth = request.headers.get("authorization", "")
    if auth == f"Bearer {API_TOKEN}":
        return
    if request.query_params.get("token") == API_TOKEN:
        return
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/api/status")
def api_status(request: Request):
    _check_token(request)
    snap = state.snapshot()
    snap["interfaces"] = get_interfaces()
    snap["auth_required"] = bool(API_TOKEN)
    return snap


@app.get("/api/interfaces")
def api_interfaces(request: Request):
    _check_token(request)
    return {"interfaces": get_interfaces()}


@app.get("/api/stats")
def api_stats(request: Request):
    _check_token(request)
    snap = state.snapshot()
    return {
        "total_flows": snap["total_flows"],
        "total_attacks": snap["total_attacks"],
        "uptime_seconds": snap["uptime"],
        "running": snap["running"],
        "model": snap["model"],
        "threshold": snap["threshold"],
    }


@app.get("/api/mitigation")
def api_mitigation_status(request: Request):
    _check_token(request)
    return mitigation.get_status()


@app.post("/api/mitigation/config")
async def api_mitigation_config(request: Request):
    _check_token(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    return mitigation.configure(
        enabled=body.get("enabled"),
        cooldown_sec=body.get("cooldown_sec"),
        threshold=body.get("threshold"),
    )


@app.post("/api/mitigation/unblock")
async def api_mitigation_unblock(request: Request):
    _check_token(request)
    try:
        body = await request.json()
        ip = str(body.get("ip", "")).strip()
    except Exception:
        ip = ""
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip' field")
    success = mitigation.unblock_ip(ip)
    return {"status": "unblocked" if success else "not_found", "ip": ip}


@app.post("/api/mitigation/block")
async def api_mitigation_block(request: Request):
    _check_token(request)
    try:
        body = await request.json()
        ip = str(body.get("ip", "")).strip()
        reason = str(body.get("reason", "Manual Block")).strip()
        dur = body.get("cooldown_sec")
    except Exception:
        ip = ""
        reason = "Manual Block"
        dur = None
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip' field")
    entry = mitigation.block_ip(ip, reason=reason, threat_score=1.0, duration_sec=dur)
    return {"status": "blocked", "entry": entry}


async def _ensure_binary_built() -> None:
    if os.path.exists(BIN_PATH):
        return

    # Prefer invoking make build if Makefile exists to leverage platform-specific CXXFLAGS/LDFLAGS
    if os.path.exists("Makefile"):
        def _build_make():
            return subprocess.run(["make", "build"], check=True, capture_output=True, text=True)

        try:
            await asyncio.to_thread(_build_make)
            return
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    cmd = [
        "g++",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Wshadow",
        "-std=c++17",
        "-pthread",
        "src/main.cpp",
        "src/sniffer.cpp",
        "src/parser.cpp",
        "src/flow.cpp",
        "src/extractor.cpp",
        "-o",
        BIN_PATH,
        "-lpcap",
    ]

    # On macOS, include Homebrew include/lib search directories if present
    if sys.platform == "darwin":
        for prefix in ["/opt/homebrew", "/usr/local"]:
            inc = Path(prefix) / "opt/libpcap/include"
            lib = Path(prefix) / "opt/libpcap/lib"
            if inc.exists():
                cmd.extend([f"-I{inc}", f"-L{lib}"])
                break

    def _build():
        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    try:
        await asyncio.to_thread(_build)
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or exc.stdout or str(exc)).strip()
        state.last_error = f"Build failed: {msg[:500]}"
        raise HTTPException(status_code=500, detail=state.last_error)


@app.post("/api/start")
async def api_start(
    request: Request,
    interface: Optional[str] = None,
    model: str = "xgb",
    threshold: float = 0.6,
):
    _check_token(request)

    # Dynamic default interface: lo0 on macOS, lo on Linux
    if not interface:
        interface = "lo0" if sys.platform == "darwin" else "lo"

    with state.lock:
        if state.proc is not None and state.proc.poll() is None:
            return {"status": "already_running"}
        state.last_error = ""

    load_ml_model(model)
    state.threshold = max(0.01, min(0.99, float(threshold)))

    try:
        await _ensure_binary_built()
    except HTTPException:
        return {"status": "error", "message": state.last_error}

    with state.lock:
        try:
            proc = subprocess.Popen(
                [BIN_PATH, interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            state.last_error = f"Binary not found: {exc}"
            return {"status": "error", "message": state.last_error}

        state.proc = proc
        state.interface = interface

    await asyncio.sleep(0.4)
    with state.lock:
        proc = state.proc
        if proc is not None and proc.poll() is not None:
            try:
                err = (proc.stderr.read() if proc.stderr else "") or ""
            except Exception:  # noqa: BLE001
                err = ""
            state.proc = None
            low = err.lower()
            if "permission" in low or "cap_net_raw" in low or "bpf" in low:
                if sys.platform == "darwin":
                    state.last_error = (
                        "Permission denied. On macOS, packet capture requires root privileges "
                        "or access to /dev/bpf*. Please run with sudo: 'sudo python3 web_app.py'."
                    )
                else:
                    state.last_error = (
                        "Permission denied. Grant capabilities with "
                        "'sudo setcap cap_net_raw=ep ./netsentinel' or run under sudo."
                    )
            else:
                state.last_error = err.strip() or "Process exited unexpectedly."
            return {"status": "error", "message": state.last_error}

        state.start_time = time.time()
        state.total_flows = 0
        state.total_attacks = 0

    return {"status": "started", "interface": interface}


@app.post("/api/stop")
def api_stop(request: Request):
    _check_token(request)
    with state.lock:
        proc = state.proc
        if proc is None or proc.poll() is not None:
            state.proc = None
            state.start_time = None
            return {"status": "not_running"}

    try:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1.0)
    except Exception:  # noqa: BLE001
        pass

    with state.lock:
        state.proc = None
        state.start_time = None
    return {"status": "stopped"}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    if API_TOKEN and websocket.query_params.get("token") != API_TOKEN:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    state.clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass
    finally:
        state.clients.discard(websocket)


# ═══════════════════════════════════════════════════════════════════════
#  Broadcast loop
# ═══════════════════════════════════════════════════════════════════════
async def broadcast_telemetry() -> None:
    tailer = FlowTailer(CSV_PATH)
    last_iface = ""
    last_heartbeat = 0.0

    while True:
        await asyncio.sleep(0.05)

        snap = state.snapshot()
        if snap["interface"] != last_iface and snap["running"]:
            tailer.reset()
            last_iface = snap["interface"]

        lines = await asyncio.to_thread(tailer.read_new_lines)

        new_flows: List[dict] = []
        batch_attacks = 0
        if lines:
            new_flows, batch_attacks = await asyncio.to_thread(
                _parse_and_score, lines, state.threshold
            )
            if new_flows:
                with state.lock:
                    state.total_flows += len(new_flows)
                    state.total_attacks += batch_attacks

        now = time.time()
        if not new_flows and not state.clients:
            continue
        if not new_flows and (now - last_heartbeat) < 1.0:
            continue
        last_heartbeat = now

        if not state.clients:
            continue

        snap = state.snapshot()
        payload = {
            "type": "telemetry",
            "running": snap["running"],
            "timestamp": now,
            "uptime": snap["uptime"],
            "total_flows": snap["total_flows"],
            "total_attacks": snap["total_attacks"],
            "new_flows": new_flows,
            "mitigation": mitigation.get_status(),
        }
        payload_str = _json_dumps(payload)

        dead: List[WebSocket] = []
        for ws in list(state.clients):
            try:
                await ws.send_text(payload_str)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            state.clients.discard(ws)


# ═══════════════════════════════════════════════════════════════════════
#  Lifecycle
# ═══════════════════════════════════════════════════════════════════════
@app.on_event("startup")
async def _on_startup() -> None:
    state.bg_task = asyncio.create_task(broadcast_telemetry())


@app.on_event("shutdown")
async def _on_shutdown() -> None:
    if state.bg_task is not None:
        state.bg_task.cancel()
        try:
            await state.bg_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        state.bg_task = None

    with state.lock:
        proc = state.proc
        state.proc = None
        state.start_time = None
    if proc is not None and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=1.5)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass


# ═══════════════════════════════════════════════════════════════════════
#  HTML
# ═══════════════════════════════════════════════════════════════════════
HTML_CONTENT = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetSentinel | Network Telemetry &amp; Analysis</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
  --bg: #090a0f;
  --bg-subtle: #0f1117;
  --panel: #13151c;
  --panel-elevated: #171a23;
  --border: #222631;
  --border-focus: #3e4456;
  --border-subtle: #191c25;

  --txt: #f1f5f9;
  --muted: #94a3b8;
  --dim: #64748b;

  --ok: #22c55e;
  --ok-dim: rgba(34, 197, 94, 0.08);
  --bad: #ef4444;
  --bad-dim: rgba(239, 68, 68, 0.08);

  --r: 4px;
  --r-sm: 2px;
  --t: .12s ease;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--txt);
  min-height: 100vh;
  font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg-subtle); }
::-webkit-scrollbar-thumb { background: #222631; border-radius: var(--r-sm); }
::-webkit-scrollbar-thumb:hover { background: #323846; }

.wrap { max-width: 1640px; margin: 0 auto; padding: 1rem 1.25rem 2rem; }
.mono { font-family: "JetBrains Mono", "SF Mono", ui-monospace, monospace; font-variant-numeric: tabular-nums; }

/* Header */
header {
  position: sticky; top: 0; z-index: 100;
  display: flex; justify-content: space-between; align-items: center; gap: 1rem;
  padding: .75rem 1rem;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--r);
  margin-bottom: 1rem;
}
.logo { display: flex; align-items: center; gap: 9px; }
.logo-title { font-size: .95rem; font-weight: 700; letter-spacing: 1.5px; color: var(--txt); }
.logo-sub { font-size: .65rem; color: var(--muted); letter-spacing: .5px; font-weight: 500; }

.hdr-right { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
.pill {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 9px; border-radius: var(--r-sm);
  font-size: .72rem; font-weight: 600; letter-spacing: .3px;
  background: var(--panel-elevated); border: 1px solid var(--border);
  color: var(--muted); transition: var(--t); white-space: nowrap;
}
.pill .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--dim); }
.pill.ok { color: var(--ok); border-color: rgba(34, 197, 94, 0.3); background: var(--ok-dim); }
.pill.ok .dot { background: var(--ok); }
.pill.bad { color: var(--bad); border-color: rgba(239, 68, 68, 0.3); background: var(--bad-dim); }
.pill.bad .dot { background: var(--bad); }

.ghbtn {
  display: inline-flex; align-items: center; gap: 5px; padding: 4px 9px; border-radius: var(--r-sm);
  background: var(--panel-elevated); border: 1px solid var(--border); color: var(--muted);
  text-decoration: none; font-size: .72rem; font-weight: 600; transition: var(--t);
}
.ghbtn:hover { color: var(--txt); border-color: var(--border-focus); }

/* Controls Deck */
.controls {
  display: grid; grid-template-columns: 1.1fr 1.1fr 1.4fr 1.3fr 95px 95px; gap: .75rem;
  padding: .75rem 1rem; background: var(--panel); border: 1px solid var(--border);
  border-radius: var(--r); margin-bottom: 1rem; align-items: end;
}
.fld { display: flex; flex-direction: column; gap: 4px; }
.fld-label { font-size: .65rem; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; font-weight: 600; }
.inp-wrap { position: relative; display: flex; align-items: center; }
.inp-wrap svg { position: absolute; right: 9px; pointer-events: none; color: var(--dim); }

select {
  width: 100%; padding: 6px 26px 6px 9px; background: var(--panel-elevated);
  border: 1px solid var(--border); color: var(--txt); border-radius: var(--r-sm);
  outline: none; font-size: .8rem; font-family: inherit; transition: var(--t); appearance: none; cursor: pointer;
}
select:hover { border-color: var(--border-focus); }
select:focus { border-color: var(--dim); }

.thr-box { display: flex; flex-direction: column; gap: 4px; }
.thr-head { display: flex; justify-content: space-between; align-items: center; }
.thr-val { font-size: .78rem; font-weight: 600; color: var(--txt); }
input[type="range"] {
  width: 100%; height: 4px; background: #222631;
  border: none; border-radius: 2px; cursor: pointer; accent-color: var(--muted); outline: none;
}

.btn {
  width: 100%; height: 32px; padding: 0 10px; border-radius: var(--r-sm); border: 1px solid var(--border);
  cursor: pointer; font-weight: 600; font-size: .75rem; letter-spacing: .4px; font-family: inherit;
  display: inline-flex; align-items: center; justify-content: center; gap: 5px; transition: var(--t);
  background: var(--panel-elevated); color: var(--txt);
}
.btn:hover:not(:disabled) { border-color: var(--border-focus); }
.btn:disabled { opacity: .35; cursor: not-allowed; }
.btn-start {
  color: var(--ok); border-color: rgba(34, 197, 94, 0.3); background: var(--ok-dim);
}
.btn-start:hover:not(:disabled) {
  border-color: var(--ok); background: rgba(34, 197, 94, 0.15);
}
.btn-stop {
  color: var(--bad); border-color: rgba(239, 68, 68, 0.3); background: var(--bad-dim);
}
.btn-stop:hover:not(:disabled) {
  border-color: var(--bad); background: rgba(239, 68, 68, 0.15);
}

/* KPI Deck */
.kpis {
  display: grid; grid-template-columns: repeat(8, 1fr); gap: .65rem; margin-bottom: 1rem;
}
.kpi {
  padding: .75rem .9rem;
  background: var(--panel); border: 1px solid var(--border); border-radius: var(--r);
  transition: border-color var(--t);
}
.kpi:hover { border-color: var(--border-focus); }
.kpi-lbl { font-size: .63rem; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; font-weight: 600; }
.kpi-val { font-size: 1.35rem; font-weight: 600; margin-top: 3px; color: var(--txt); letter-spacing: -.3px; }
.kpi-foot { font-size: .65rem; color: var(--dim); margin-top: 3px; display: flex; align-items: center; gap: 4px; }
.trend { font-weight: 600; }
.trend.up { color: var(--bad); }
.trend.ok { color: var(--ok); }
.trend.flat { color: var(--dim); }

/* Panels & Grids */
.grid-2 { display: grid; grid-template-columns: 2fr 1fr; gap: .75rem; margin-bottom: .75rem; }
.grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: .75rem; margin-bottom: .75rem; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: var(--r); padding: .85rem .95rem; }

.phead { display: flex; align-items: center; justify-content: space-between; margin-bottom: .65rem; gap: .5rem; flex-wrap: wrap; }
.ptitle { font-size: .72rem; font-weight: 600; color: var(--txt); text-transform: uppercase; letter-spacing: .6px; display: flex; align-items: center; gap: 6px; }
.pbadge { font-size: .63rem; padding: 2px 6px; border-radius: var(--r-sm); background: var(--panel-elevated); border: 1px solid var(--border); color: var(--muted); font-weight: 600; }
.pbadge.red { background: var(--bad-dim); color: var(--bad); border-color: rgba(239, 68, 68, 0.3); }

.chart-box { position: relative; width: 100%; height: 215px; }
.chart-box.short { height: 165px; }
.chart-box canvas { display: block; width: 100%!important; height: 100%!important; }

/* Alerts Feed */
.legend { display: flex; gap: .5rem; font-size: .65rem; color: var(--dim); align-items: center; }
.lg { display: inline-flex; align-items: center; gap: 4px; }
.swatch { width: 6px; height: 6px; border-radius: 1px; }
#alerts { max-height: 290px; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; padding-right: 2px; }
.empty {
  color: var(--dim); font-size: .76rem; text-align: center; padding: 2rem 0;
  display: flex; flex-direction: column; align-items: center; gap: 6px;
}
.empty svg { color: var(--dim); }
.alert {
  display: flex; flex-direction: column; gap: 2px; padding: 6px 8px; border-radius: var(--r-sm);
  background: var(--panel-elevated); border: 1px solid var(--border); border-left: 3px solid var(--bad);
  font-size: .74rem;
}
.alert.critical { border-left-color: var(--bad); }
.alert.high { border-left-color: #f87171; }
.alert.medium { border-left-color: #fbbf24; }
.a-head { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
.a-head strong { font-weight: 600; font-family: "JetBrains Mono", monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sev { font-size: .58rem; font-weight: 600; padding: 1px 4px; border-radius: 2px; letter-spacing: .3px; }
.sev.critical { background: var(--bad-dim); color: var(--bad); }
.sev.high { background: rgba(248, 113, 113, 0.1); color: #f87171; }
.sev.medium { background: rgba(251, 191, 36, 0.1); color: #fbbf24; }
.a-body { display: flex; justify-content: space-between; gap: 6px; font-size: .68rem; color: var(--muted); }
.a-body .score { color: var(--bad); font-weight: 600; }
.a-time { color: var(--dim); font-size: .66rem; }
.btn-ghost {
  font-size: .64rem; padding: 2px 7px; border-radius: var(--r-sm);
  background: transparent; color: var(--muted); border: 1px solid var(--border);
  cursor: pointer; font-weight: 600; transition: var(--t); font-family: inherit;
}
.btn-ghost:hover { color: var(--bad); border-color: rgba(239, 68, 68, 0.35); }

/* Top Talkers */
#talkers { display: flex; flex-direction: column; gap: 4px; }
.talker {
  display: grid; grid-template-columns: 1fr auto; gap: 5px; align-items: center;
  padding: 5px 7px; border-radius: var(--r-sm); background: var(--panel-elevated);
  border: 1px solid var(--border-subtle); font-size: .74rem;
}
.talker .ip { color: var(--txt); font-family: "JetBrains Mono", monospace; overflow: hidden; text-overflow: ellipsis; }
.talker .sz { color: var(--muted); font-weight: 600; font-variant-numeric: tabular-nums; }
.talker .bar { grid-column: 1/-1; height: 2px; border-radius: 1px; background: #222631; overflow: hidden; }
.talker .bar > i { display: block; height: 100%; background: var(--muted); }

/* Focus Metric List */
.focus-list { display: flex; flex-direction: column; gap: .45rem; font-size: .76rem; }
.focus-row { display: flex; justify-content: space-between; align-items: center; padding: 2px 0; border-bottom: 1px solid var(--border-subtle); }
.focus-row:last-child { border-bottom: none; }
.focus-lbl { color: var(--muted); }
.focus-val { font-weight: 600; color: var(--txt); }

/* Flow Table */
.table-panel { background: var(--panel); border: 1px solid var(--border); border-radius: var(--r); overflow: hidden; margin-bottom: 1rem; }
.tp-head { display: flex; align-items: center; justify-content: space-between; padding: .65rem .95rem; border-bottom: 1px solid var(--border); background: var(--panel-elevated); gap: .5rem; flex-wrap: wrap; }
.tp-tools { display: flex; gap: .4rem; align-items: center; flex-wrap: wrap; }
.search-wrap { position: relative; display: inline-flex; align-items: center; }
.search-wrap svg { position: absolute; left: 7px; color: var(--dim); pointer-events: none; }
.search {
  padding: 4px 8px 4px 24px; background: var(--panel); border: 1px solid var(--border);
  color: var(--txt); border-radius: var(--r-sm); font-size: .73rem; outline: none; font-family: inherit;
  width: 170px; transition: var(--t);
}
.search:focus { border-color: var(--border-focus); width: 210px; }

.btn-mini {
  font-size: .67rem; padding: 3px 8px; border-radius: var(--r-sm);
  background: var(--panel); color: var(--muted); border: 1px solid var(--border);
  cursor: pointer; font-weight: 600; transition: var(--t); font-family: inherit;
}
.btn-mini:hover { color: var(--txt); border-color: var(--border-focus); }
.btn-mini.on { background: var(--panel-elevated); color: var(--txt); border-color: var(--dim); }

.tbl-wrap { overflow: auto; max-height: 450px; }
table { width: 100%; border-collapse: collapse; font-size: .74rem; text-align: left; }
thead { position: sticky; top: 0; z-index: 5; background: var(--panel-elevated); }
th {
  padding: 7px 9px; color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: .62rem;
  letter-spacing: .5px; white-space: nowrap; cursor: pointer; user-select: none;
  border-bottom: 1px solid var(--border); transition: color var(--t);
}
th:hover { color: var(--txt); }
th.sorted { color: var(--txt); }
th .arr { opacity: .35; margin-left: 2px; font-size: .6rem; }
th.sorted .arr { opacity: 1; }
td { padding: 5px 9px; border-bottom: 1px solid var(--border-subtle); vertical-align: middle; white-space: nowrap; font-family: "JetBrains Mono", monospace; font-size: .71rem; }
tbody tr:hover { background: var(--panel-elevated); }
tbody tr.attack { background: rgba(239, 68, 68, 0.04); }
tbody tr.attack:hover { background: rgba(239, 68, 68, 0.08); }

.proto { display: inline-block; padding: 1px 5px; border-radius: var(--r-sm); font-size: .63rem; font-weight: 600; background: var(--panel-elevated); color: var(--muted); border: 1px solid var(--border-subtle); }

.badge { display: inline-block; padding: 1px 5px; border-radius: var(--r-sm); font-size: .63rem; font-weight: 600; }
.badge.atk { background: var(--bad-dim); color: var(--bad); border: 1px solid rgba(239, 68, 68, 0.25); }
.badge.ben { background: var(--ok-dim); color: var(--ok); border: 1px solid rgba(34, 197, 94, 0.25); }

.score-wrap { display: flex; align-items: center; gap: 5px; min-width: 75px; }
.score-bar { height: 3px; border-radius: 1px; flex: 1; min-width: 36px; background: #222631; overflow: hidden; }
.score-fill { height: 100%; border-radius: 1px; }
.score-num { font-size: .68rem; min-width: 32px; text-align: right; font-weight: 600; }

/* Footer */
footer {
  display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap;
  padding-top: .85rem; font-size: .67rem; color: var(--dim); border-top: 1px solid var(--border);
}
footer a { color: var(--muted); text-decoration: none; }
footer a:hover { color: var(--txt); }
footer .stats { display: flex; gap: .75rem; font-family: "JetBrains Mono", monospace; }
footer .stats b { color: var(--muted); font-weight: 600; }

/* Toast */
#toast {
  position: fixed; bottom: 1rem; right: 1rem; z-index: 9999; max-width: 380px;
  background: var(--panel); border: 1px solid var(--bad); color: var(--txt);
  border-radius: var(--r-sm); padding: .7rem .9rem; font-size: .78rem; line-height: 1.4;
  transform: translateY(140%); transition: transform .2s ease;
}
#toast.show { transform: translateY(0); }
#toast strong { display: block; margin-bottom: 2px; font-size: .8rem; color: var(--bad); }

@media (max-width: 1380px) {
  .kpis { grid-template-columns: repeat(4, 1fr); }
  .controls { grid-template-columns: 1fr 1fr; }
  .grid-3 { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 820px) {
  .kpis { grid-template-columns: repeat(2, 1fr); }
  .grid-2, .grid-3 { grid-template-columns: 1fr; }
  .controls { grid-template-columns: 1fr; }
  .logo-sub { display: none; }
}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="logo">
      <div class="logo-title">NETSENTINEL</div>
      <div class="logo-sub">Network Telemetry &amp; Analysis</div>
    </div>
    <div class="hdr-right">
      <a href="https://github.com/monkonthehill/NetSenital" target="_blank" rel="noopener" class="ghbtn" title="View Source">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
        GitHub
      </a>
      <div class="pill mono" id="uptimePill">00:00:00</div>
      <div class="pill" id="connPill" title="WebSocket status">
        <span class="dot"></span><span id="connText">CONNECTING</span>
      </div>
      <div class="pill" id="statusPill">
        <span class="dot"></span><span id="statusText">IDLE</span>
      </div>
    </div>
  </header>

  <div class="controls">
    <div class="fld">
      <div class="fld-label">Capture Interface</div>
      <div class="inp-wrap">
        <select id="iface"><option>Loading...</option></select>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m6 9 6 6 6-6"/></svg>
      </div>
    </div>
    <div class="fld">
      <div class="fld-label">Detection Model</div>
      <div class="inp-wrap">
        <select id="model">
          <option value="xgb" selected>XGBoost (19-Feature)</option>
          <option value="rf">Random Forest</option>
        </select>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m6 9 6 6 6-6"/></svg>
      </div>
    </div>
    <div class="thr-box">
      <div class="thr-head">
        <span class="fld-label">Anomaly Threshold</span>
        <span class="thr-val mono" id="thrVal">0.60</span>
      </div>
      <input type="range" id="thr" min=".10" max=".99" step=".01" value=".60">
    </div>
    <div class="fld">
      <div class="fld-label">Auto-Block (IPS)</div>
      <div style="display:flex;gap:6px;align-items:center">
        <button class="btn" id="autoBlockBtn" style="height:32px;flex:1;background:var(--bad-dim);color:var(--bad);border-color:rgba(239,68,68,0.3)" title="Toggle automatic firewall blocking for >=98% certainty threats">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span id="autoBlockTxt">ACTIVE</span>
        </button>
        <div class="inp-wrap" style="width:72px">
          <select id="cooldownSelect" style="padding-right:20px" title="Auto-unblock cooldown timer">
            <option value="30">30s</option>
            <option value="60" selected>60s</option>
            <option value="120">120s</option>
            <option value="300">300s</option>
          </select>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m6 9 6 6 6-6"/></svg>
        </div>
      </div>
    </div>
    <button class="btn btn-start" id="startBtn">START</button>
    <button class="btn btn-stop" id="stopBtn" disabled>STOP</button>
  </div>

  <div class="kpis">
    <div class="kpi">
      <div class="kpi-lbl">Total Flows</div>
      <div class="kpi-val mono" id="kFlows">0</div>
      <div class="kpi-foot"><span class="trend flat" id="kFlowsT">session total</span></div>
    </div>
    <div class="kpi">
      <div class="kpi-lbl">Throughput</div>
      <div class="kpi-val mono" id="kBps">0 KB/s</div>
      <div class="kpi-foot"><span class="trend flat" id="kBpsT">current rate</span></div>
    </div>
    <div class="kpi">
      <div class="kpi-lbl">Packets / Sec</div>
      <div class="kpi-val mono" id="kPps">0</div>
      <div class="kpi-foot">current rate</div>
    </div>
    <div class="kpi">
      <div class="kpi-lbl">Attacks Flagged</div>
      <div class="kpi-val mono" id="kAtk" style="color:var(--bad)">0</div>
      <div class="kpi-foot"><span class="trend flat" id="kAtkT">all clean</span></div>
    </div>
    <div class="kpi">
      <div class="kpi-lbl">Anomaly Rate</div>
      <div class="kpi-val mono" id="kRate">0.0%</div>
      <div class="kpi-foot">of total traffic</div>
    </div>
    <div class="kpi">
      <div class="kpi-lbl">Avg Packet Size</div>
      <div class="kpi-val mono" id="kAvg">0 B</div>
      <div class="kpi-foot">bytes / packet</div>
    </div>
    <div class="kpi">
      <div class="kpi-lbl">CPU Usage</div>
      <div class="kpi-val mono" id="kCpu">0.0%</div>
      <div class="kpi-foot"><span class="trend flat" id="kCpuT">system load</span></div>
    </div>
    <div class="kpi">
      <div class="kpi-lbl">Memory Usage</div>
      <div class="kpi-val mono" id="kMem">0.0%</div>
      <div class="kpi-foot"><span class="trend flat" id="kMemT">heap / runtime</span></div>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <div class="phead">
        <div class="ptitle">Throughput &amp; PPS</div>
        <span class="pbadge" id="ptsBadge">60 pts</span>
      </div>
      <div class="chart-box"><canvas id="chartTraffic"></canvas></div>
    </div>
    <div class="panel">
      <div class="phead">
        <div class="ptitle">
          Security Alerts
          <span class="pbadge red" id="atkBadge">0</span>
        </div>
        <div style="display:flex;gap:.5rem;align-items:center">
          <div class="legend">
            <span class="lg"><span class="swatch" style="background:var(--bad)"></span>Crit</span>
            <span class="lg"><span class="swatch" style="background:#f87171"></span>High</span>
            <span class="lg"><span class="swatch" style="background:#fbbf24"></span>Med</span>
          </div>
          <button class="btn-ghost" id="clearAlerts">CLEAR</button>
        </div>
      </div>
      <div id="alerts">
        <div class="empty">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
          No threat alerts detected
        </div>
      </div>
    </div>
  </div>

  <div class="grid-3">
    <div class="panel">
      <div class="phead">
        <div class="ptitle">Protocol Breakdown</div>
      </div>
      <div class="chart-box short"><canvas id="chartProto"></canvas></div>
    </div>
    <div class="panel">
      <div class="phead">
        <div class="ptitle">TCP Flags</div>
      </div>
      <div class="chart-box short"><canvas id="chartFlags"></canvas></div>
    </div>
    <div class="panel">
      <div class="phead">
        <div class="ptitle">Threat Timeline</div>
        <span class="pbadge" id="thrBadge">thr 0.60</span>
      </div>
      <div class="chart-box short"><canvas id="chartThreat"></canvas></div>
    </div>
  </div>

  <div class="grid-2" style="grid-template-columns:2fr 1fr">
    <div class="panel">
      <div class="phead">
        <div class="ptitle">Bandwidth Leaders (IP)</div>
      </div>
      <div id="talkers">
        <div class="empty" style="padding:1.2rem 0">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49"/></svg>
          Awaiting traffic flows...
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="phead">
        <div class="ptitle">Session Focus</div>
      </div>
      <div class="focus-list">
        <div class="focus-row"><span class="focus-lbl">Model</span><span class="mono focus-val" id="focusModel">—</span></div>
        <div class="focus-row"><span class="focus-lbl">Interface</span><span class="mono focus-val" id="focusIface">—</span></div>
        <div class="focus-row"><span class="focus-lbl">Threshold</span><span class="mono focus-val" id="focusThr">—</span></div>
        <div class="focus-row"><span class="focus-lbl">Uptime</span><span class="mono focus-val" id="focusUp">—</span></div>
        <div class="focus-row"><span class="focus-lbl">CPU Load</span><span class="mono focus-val" id="focusCpu">0.0%</span></div>
        <div class="focus-row"><span class="focus-lbl">Memory Usage</span><span class="mono focus-val" id="focusMem">0.0%</span></div>
        <div class="focus-row"><span class="focus-lbl">Unique Sources</span><span class="mono focus-val" id="focusSrc">0</span></div>
        <div class="focus-row"><span class="focus-lbl">Unique Destinations</span><span class="mono focus-val" id="focusDst">0</span></div>
      </div>
    </div>
  </div>

  <div class="panel" id="blockedPanel" style="margin-bottom:0.75rem">
    <div class="phead">
      <div class="ptitle">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><circle cx="12" cy="11" r="3"/></svg>
        Firewall Mitigation &amp; Auto-Block Active Defense
        <span class="pbadge" id="blockedCountBadge">0 BLOCKED</span>
      </div>
      <div style="font-size:0.68rem;color:var(--dim)">
        Auto-blocks threats with &ge;98% certainty &bull; Unblocks automatically after cooldown
      </div>
    </div>
    <div id="blockedList" style="display:flex;flex-wrap:wrap;gap:8px;min-height:36px;align-items:center">
      <div class="empty" style="padding:0.6rem 0;width:100%">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
        No IPs currently blocked &mdash; network traffic clear
      </div>
    </div>
  </div>

  <div class="table-panel">
    <div class="tp-head">
      <div class="ptitle">Live Flow Telemetry</div>
      <div class="tp-tools">
        <div class="search-wrap">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input class="search" id="search" placeholder="Filter address / port...">
        </div>
        <button class="btn-mini" id="atkOnly">ATTACKS ONLY</button>
        <button class="btn-mini" id="pauseBtn">PAUSE</button>
        <button class="btn-mini" id="exportBtn">EXPORT CSV</button>
      </div>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr>
          <th data-k="src">Source<span class="arr">^</span></th>
          <th data-k="dst">Destination<span class="arr">^</span></th>
          <th data-k="proto">Proto<span class="arr">^</span></th>
          <th data-k="packets">Packets (F/B)<span class="arr">^</span></th>
          <th data-k="bytes">Bytes<span class="arr">^</span></th>
          <th data-k="dur">Duration<span class="arr">^</span></th>
          <th data-k="bps">Rate<span class="arr">^</span></th>
          <th data-k="score" class="sorted">Threat<span class="arr">v</span></th>
          <th>Verdict</th>
        </tr></thead>
        <tbody id="tbody">
          <tr><td colspan="9" style="text-align:center;color:var(--dim);padding:2rem">Start capture to stream flow records...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <footer>
    <div>NetSentinel NIDS &middot; Machine Learning Threat Engine &middot; <a href="https://github.com/monkonthehill/NetSenital" target="_blank" rel="noopener">github.com/monkonthehill/NetSenital</a></div>
    <div class="stats">
      <span><b>MSG/S</b> <span id="fMsgps">0</span></span>
      <span><b>RENDER</b> <span id="fFps">—</span></span>
    </div>
  </footer>
</div>

<div id="toast"></div>

<script>
/* Constants & State */
const TOKEN = new URLSearchParams(location.search).get('token') || '';
const WS_URL = (location.protocol === 'https:' ? 'wss:' : 'ws:')
             + '//' + location.host + '/ws' + (TOKEN ? '?token=' + encodeURIComponent(TOKEN) : '');

const CHART_WINDOW = 60;
const TABLE_POOL   = 30;

let totalFlows = 0, totalAttacks = 0, alertCount = 0;
let flowList = [];
let paused = false;
let attacksOnly = false;
let filter = '';
let sortKey = 'score', sortAsc = false;

const bpsW = Array(CHART_WINDOW).fill(0);
const ppsW = Array(CHART_WINDOW).fill(0);

const protoCounts = { TCP:0, UDP:0, ICMP:0, OTHER:0 };
const flagCounts  = { SYN:0, ACK:0, FIN:0, RST:0, PSH:0, URG:0 };
const threatPoints = [];
const talkers = new Map();

let currentThreshold = 0.60;
let wsConnected = false;
let ws, wsRetry = 0;
let captureStartTs = null, captureTimer = null;
let renderPending = false;
let lastRenderTs = 0;
let msgCount = 0, lastMsgTs = Date.now();

document.getElementById('ptsBadge').textContent = CHART_WINDOW + ' pts';

/* Chart.js Minimal Configurations */
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.size = 10;
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace';

const cTraffic = new Chart(document.getElementById('chartTraffic'), {
  type: 'line',
  data: {
    labels: Array(CHART_WINDOW).fill(''),
    datasets: [
      {
        label: 'KB/s',
        borderColor: '#94a3b8',
        backgroundColor: 'rgba(148,163,184,0.06)',
        data: bpsW,
        tension: 0.2,
        fill: true,
        pointRadius: 0,
        borderWidth: 1.5
      },
      {
        label: 'PPS',
        borderColor: '#e2e8f0',
        data: ppsW,
        tension: 0.2,
        yAxisID: 'y1',
        pointRadius: 0,
        borderWidth: 1.2
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    resizeDelay: 150,
    animation: { duration: 180, easing: 'easeOutQuad' },
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: { display: false },
      y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', font: { size: 9 } } },
      y1: { position: 'right', grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 9 } } }
    },
    plugins: {
      legend: { labels: { color: '#94a3b8', font: { size: 9 }, boxWidth: 8 } },
      tooltip: {
        backgroundColor: '#13151c',
        borderColor: '#222631',
        borderWidth: 1,
        titleColor: '#f1f5f9',
        bodyColor: '#94a3b8',
        padding: 6,
        cornerRadius: 2
      }
    }
  }
});

const cProto = new Chart(document.getElementById('chartProto'), {
  type: 'doughnut',
  data: {
    labels: ['TCP', 'UDP', 'ICMP', 'OTHER'],
    datasets: [{
      data: [0, 0, 0, 0],
      backgroundColor: ['#e2e8f0', '#94a3b8', '#64748b', '#334155'],
      borderColor: '#13151c',
      borderWidth: 1,
      hoverOffset: 3
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    resizeDelay: 150,
    animation: { duration: 250, animateRotate: true, easing: 'easeOutQuad' },
    cutout: '70%',
    plugins: {
      legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 9 }, padding: 6, boxWidth: 7 } }
    }
  }
});

const cFlags = new Chart(document.getElementById('chartFlags'), {
  type: 'bar',
  data: {
    labels: ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'],
    datasets: [{
      label: 'count',
      data: [0, 0, 0, 0, 0, 0],
      backgroundColor: '#94a3b8',
      borderColor: '#64748b',
      borderWidth: 1,
      borderRadius: 1
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    resizeDelay: 150,
    animation: { duration: 200, easing: 'easeOutQuad' },
    scales: {
      x: { ticks: { color: '#94a3b8', font: { size: 9 } }, grid: { display: false } },
      y: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.03)' } }
    },
    plugins: { legend: { display: false } }
  }
});

const threatThresholdPlugin = {
  id: 'thrLine',
  afterDraw(chart) {
    const { ctx, chartArea, scales } = chart;
    if (!chartArea || !scales.y) return;
    const y = scales.y.getPixelForValue(currentThreshold);
    if (y < chartArea.top || y > chartArea.bottom) return;
    ctx.save();
    ctx.setLineDash([3, 3]);
    ctx.strokeStyle = 'rgba(239,68,68,0.45)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(chartArea.left, y);
    ctx.lineTo(chartArea.right, y);
    ctx.stroke();
    ctx.fillStyle = 'rgba(239,68,68,0.7)';
    ctx.font = '9px monospace';
    ctx.fillText(`thr ${currentThreshold.toFixed(2)}`, chartArea.left + 4, y - 3);
    ctx.restore();
  }
};

const cThreat = new Chart(document.getElementById('chartThreat'), {
  type: 'scatter',
  data: {
    datasets: [
      { label: 'Benign', data: [], backgroundColor: '#64748b', pointRadius: 2, pointHoverRadius: 3 },
      { label: 'Attack', data: [], backgroundColor: '#ef4444', pointRadius: 3, pointHoverRadius: 4 }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    resizeDelay: 150,
    animation: false,
    scales: {
      x: { display: false },
      y: { min: 0, max: 1, ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.03)' } }
    },
    plugins: {
      legend: { labels: { color: '#94a3b8', font: { size: 9 }, boxWidth: 7 } }
    }
  },
  plugins: [threatThresholdPlugin]
});

/* Helpers */
const $ = id => document.getElementById(id);
const fmtBytes = n => n < 1024 ? n + ' B'
  : n < 1048576 ? (n / 1024).toFixed(1) + ' KB'
  : n < 1073741824 ? (n / 1048576).toFixed(2) + ' MB'
  : (n / 1073741824).toFixed(2) + ' GB';

const relTime = ms => {
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 5) return 'now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  return Math.floor(s / 3600) + 'h ago';
};
const protoName = p => p === 6 ? 'TCP' : p === 17 ? 'UDP' : p === 1 ? 'ICMP' : 'OTHER';

function showToast(title, msg) {
  const t = $('toast');
  t.innerHTML = '';
  const s = document.createElement('strong'); s.textContent = title;
  const m = document.createElement('div'); m.textContent = msg;
  t.append(s, m);
  t.classList.add('show');
  clearTimeout(t._t);
  t._t = setTimeout(() => t.classList.remove('show'), 6500);
}

/* KPI Number Tweening */
function tween(el, target, fmt, dur = 200) {
  const start = el._v ?? 0;
  if (start === target) { el.textContent = fmt(target); return; }
  const t0 = performance.now();
  cancelAnimationFrame(el._raf);
  const step = t => {
    const k = Math.min(1, (t - t0) / dur);
    const e = 1 - Math.pow(1 - k, 2);
    const v = start + (target - start) * e;
    el.textContent = fmt(v);
    if (k < 1) el._raf = requestAnimationFrame(step);
    else el._v = target;
  };
  el._raf = requestAnimationFrame(step);
  el._v = target;
}

/* Status */
async function fetchStatus() {
  try {
    const r = await fetch('/api/status' + (TOKEN ? '?token=' + TOKEN : ''));
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();

    const sel = $('iface');
    sel.innerHTML = '';
    (d.interfaces || []).forEach(i => {
      const o = document.createElement('option');
      o.value = i; o.textContent = i;
      sel.appendChild(o);
    });
    if (d.interface && d.interfaces.includes(d.interface)) sel.value = d.interface;

    $('thr').value = d.threshold;
    $('thrVal').textContent = Number(d.threshold).toFixed(2);
    currentThreshold = Number(d.threshold);
    $('thrBadge').textContent = 'thr ' + currentThreshold.toFixed(2);
    $('model').value = d.model || 'xgb';

    $('focusModel').textContent = d.model || '—';
    $('focusIface').textContent = d.interface || '—';
    $('focusThr').textContent = Number(d.threshold).toFixed(2);

    updateRunUI(d.running);
    if (d.error && d.error.trim()) showToast('Capture Error', d.error);
  } catch (e) {
    console.warn('fetchStatus:', e);
  }
}

function updateRunUI(running) {
  const sp = $('statusPill'), st = $('statusText');
  const up = $('uptimePill');
  if (running) {
    sp.classList.add('ok'); sp.classList.remove('bad');
    st.textContent = 'LIVE';
    up.classList.add('ok');
  } else {
    sp.classList.remove('ok', 'bad');
    st.textContent = 'IDLE';
    up.classList.remove('ok');
    if (!captureStartTs) up.textContent = '00:00:00';
  }
  $('startBtn').disabled = running;
  $('stopBtn').disabled = !running;
}

/* Capture Controls */
async function startCapture() {
  const iface = $('iface').value;
  const model = $('model').value;
  const thr = parseFloat($('thr').value);
  $('startBtn').disabled = true;
  try {
    const qs = new URLSearchParams({ interface: iface, model, threshold: thr });
    if (TOKEN) qs.set('token', TOKEN);
    const r = await fetch('/api/start?' + qs, {
      method: 'POST',
      headers: TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {}
    });
    const d = await r.json();
    if (d.status === 'error') {
      showToast('Capture Error', d.message);
      updateRunUI(false);
    } else {
      updateRunUI(true);
      resetSession();
      startTimer();
      $('focusIface').textContent = iface;
      $('focusModel').textContent = model;
      $('focusThr').textContent = thr.toFixed(2);
      currentThreshold = thr;
      $('thrBadge').textContent = 'thr ' + thr.toFixed(2);
      cThreat.draw();
    }
  } catch (e) {
    showToast('Network Error', String(e));
  } finally {
    $('startBtn').disabled = $('statusPill').classList.contains('ok');
  }
}

async function stopCapture() {
  try {
    const qs = TOKEN ? '?token=' + TOKEN : '';
    await fetch('/api/stop' + qs, {
      method: 'POST',
      headers: TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {}
    });
  } finally {
    updateRunUI(false);
    stopTimer();
  }
}

function resetSession() {
  totalFlows = 0; totalAttacks = 0; alertCount = 0;
  flowList = [];
  talkers.clear();
  protoCounts.TCP = protoCounts.UDP = protoCounts.ICMP = protoCounts.OTHER = 0;
  Object.keys(flagCounts).forEach(k => flagCounts[k] = 0);
  threatPoints.length = 0;
  bpsW.fill(0); ppsW.fill(0);
  $('alerts').innerHTML = '<div class="empty"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>No threat alerts detected</div>';
  $('atkBadge').textContent = '0';
  $('kFlows')._v = $('kBps')._v = $('kAtk')._v = $('kPps')._v = $('kAvg')._v = $('kRate')._v = 0;
  renderTalkers();
}

/* Timer */
function startTimer(fromUptime) {
  if (fromUptime != null) captureStartTs = Date.now() - fromUptime * 1000;
  else if (!captureStartTs) captureStartTs = Date.now();
  stopTimer(true);
  captureTimer = setInterval(tickTimer, 1000);
  tickTimer();
}
function tickTimer() {
  if (!captureStartTs) return;
  const e = Math.floor((Date.now() - captureStartTs) / 1000);
  const h = String(Math.floor(e / 3600)).padStart(2, '0');
  const m = String(Math.floor((e % 3600) / 60)).padStart(2, '0');
  const s = String(e % 60).padStart(2, '0');
  $('uptimePill').textContent = `${h}:${m}:${s}`;
  $('focusUp').textContent = `${h}:${m}:${s}`;
}
function stopTimer(keepTs) {
  if (captureTimer) { clearInterval(captureTimer); captureTimer = null; }
  if (!keepTs) { captureStartTs = null; $('uptimePill').textContent = '00:00:00'; }
}

/* WebSocket */
function setConn(ok) {
  wsConnected = ok;
  const p = $('connPill'), t = $('connText');
  p.classList.remove('ok', 'bad');
  if (ok) { p.classList.add('ok'); t.textContent = 'WS LIVE'; }
  else    { p.classList.add('bad'); t.textContent = 'DISCONNECTED'; }
}

function connectWS() {
  try { ws = new WebSocket(WS_URL); }
  catch (e) { setTimeout(connectWS, 1500); return; }

  ws.onopen = () => { wsRetry = 0; setConn(true); };
  ws.onclose = () => {
    setConn(false);
    wsRetry = Math.min(wsRetry + 1, 6);
    setTimeout(connectWS, Math.min(1000 * Math.pow(1.5, wsRetry), 8000));
  };
  ws.onerror = () => { try { ws.close(); } catch (_) {} };
  ws.onmessage = ev => {
    msgCount++;
    let d;
    try { d = JSON.parse(ev.data); } catch (_) { return; }
    if (d.type !== 'telemetry') return;

    updateRunUI(d.running);
    if (d.running) startTimer(d.uptime);

    if (d.mitigation) updateMitigationUI(d.mitigation);

    if (d.new_flows && d.new_flows.length && !paused) ingest(d.new_flows);
  };
}

/* Ingestion */
function ingest(flows) {
  let sumBps = 0, sumPps = 0, sumSize = 0, newAtk = 0;
  const tNow = Date.now() / 1000;

  for (let i = 0; i < flows.length; i++) {
    const f = flows[i];
    sumBps  += f.bytesPerSecond;
    sumPps  += f.packetsPerSecond;
    sumSize += f.averagePacketSize || 0;

    const proto = protoName(f.protocol);
    protoCounts[proto] = (protoCounts[proto] || 0) + 1;

    flagCounts.SYN += f.synCount || 0;
    flagCounts.ACK += f.ackCount || 0;
    flagCounts.FIN += f.finCount || 0;
    flagCounts.RST += f.rstCount || 0;
    flagCounts.PSH += f.pshCount || 0;
    flagCounts.URG += f.urgCount || 0;

    threatPoints.push({ x: tNow, y: f.threat_score, a: f.is_anomaly });
    if (threatPoints.length > 120) threatPoints.shift();

    if (f.is_anomaly) { newAtk++; addAlert(f); }

    const k = f.srcIp;
    const tk = talkers.get(k) || { bytes: 0, pkts: 0 };
    tk.bytes += f.bytes; tk.pkts += f.packets;
    talkers.set(k, tk);

    flowList.unshift(f);
  }
  if (flowList.length > 100) flowList.length = 100;

  totalFlows   += flows.length;
  totalAttacks += newAtk;

  const kbps = sumBps / 1024;
  const avg  = flows.length ? sumSize / flows.length : 0;
  const rate = totalFlows ? (totalAttacks / totalFlows) * 100 : 0;

  tween($('kFlows'), totalFlows, v => Math.round(v).toLocaleString());
  tween($('kBps'),   kbps,       v => v.toFixed(1) + ' KB/s');
  tween($('kAtk'),   totalAttacks, v => Math.round(v).toLocaleString());
  tween($('kRate'),  rate,       v => v.toFixed(1) + '%');
  tween($('kAvg'),   avg,        v => v.toFixed(0) + ' B');
  tween($('kPps'),   sumPps,     v => Math.round(v).toString());

  const at = $('kAtkT');
  if (newAtk > 0) { at.textContent = `+${newAtk} new`; at.className = 'trend up'; }
  else            { at.textContent = 'all clean';     at.className = 'trend ok'; }

  bpsW.shift(); bpsW.push(kbps);
  ppsW.shift(); ppsW.push(sumPps);

  if (!renderPending) {
    renderPending = true;
    requestAnimationFrame(() => {
      renderPending = false;
      flushCharts();
      renderTable();
    });
  }
}

/* Chart Updates */
function flushCharts() {
  cTraffic.update('none');

  const pd = cProto.data.datasets[0].data;
  pd[0] = protoCounts.TCP; pd[1] = protoCounts.UDP;
  pd[2] = protoCounts.ICMP; pd[3] = protoCounts.OTHER;
  cProto.update('none');

  const fd = cFlags.data.datasets[0].data;
  fd[0] = flagCounts.SYN; fd[1] = flagCounts.ACK;
  fd[2] = flagCounts.FIN; fd[3] = flagCounts.RST;
  fd[4] = flagCounts.PSH; fd[5] = flagCounts.URG;
  cFlags.update('none');

  const ben = [], atk = [];
  for (const p of threatPoints) (p.a ? atk : ben).push({ x: p.x, y: p.y });
  cThreat.data.datasets[0].data = ben;
  cThreat.data.datasets[1].data = atk;
  cThreat.update('none');

  renderTalkers();
}

function renderTalkers() {
  const el = $('talkers');
  const top = [...talkers.entries()].sort((a, b) => b[1].bytes - a[1].bytes).slice(0, 5);
  if (!top.length) {
    el.innerHTML = '<div class="empty" style="padding:1.2rem 0"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49"/></svg>Awaiting traffic flows...</div>';
    $('focusSrc').textContent = '0';
    $('focusDst').textContent = '0';
    return;
  }
  const max = top[0][1].bytes || 1;
  el.innerHTML = '';
  for (const [ip, v] of top) {
    const row = document.createElement('div');
    row.className = 'talker';
    const ipEl = document.createElement('div');
    ipEl.className = 'ip'; ipEl.textContent = ip;
    const szEl = document.createElement('div');
    szEl.className = 'sz'; szEl.textContent = fmtBytes(v.bytes);
    const bar = document.createElement('div');
    bar.className = 'bar';
    const fill = document.createElement('i');
    fill.style.width = Math.max(4, (v.bytes / max) * 100) + '%';
    bar.appendChild(fill);
    row.append(ipEl, szEl, bar);
    el.appendChild(row);
  }
  $('focusSrc').textContent = talkers.size;
  const dstSet = new Set();
  for (const f of flowList) dstSet.add(f.dstIp);
  $('focusDst').textContent = dstSet.size;
}

/* Alerts Feed */
function sevOf(score) {
  if (score >= 0.9) return 'critical';
  if (score >= 0.7) return 'high';
  return 'medium';
}

function addAlert(f) {
  const c = $('alerts');
  const empty = c.querySelector('.empty');
  if (empty) c.innerHTML = '';

  const sev = sevOf(f.threat_score);
  const pct = (f.threat_score * 100).toFixed(1);
  const target = f.dstPort === 80 ? 'HTTP'
              : f.dstPort === 443 ? 'HTTPS'
              : f.dstPort === 22 ? 'SSH'
              : ':' + f.dstPort;

  const item = document.createElement('div');
  item.className = 'alert ' + sev;

  const atkName = (f.attack_type && f.attack_type !== 'Benign') ? f.attack_type.toUpperCase() : 'ATTACK';
  const head = document.createElement('div'); head.className = 'a-head';
  const strong = document.createElement('strong');
  strong.textContent = `${atkName} · ${target} · ${f.srcIp} -> ${f.dstIp}`;
  const sevB = document.createElement('span');
  sevB.className = 'sev ' + sev; sevB.textContent = sev.toUpperCase();
  head.append(strong, sevB);

  const body = document.createElement('div'); body.className = 'a-body';
  const score = document.createElement('span');
  score.className = 'score'; score.textContent = 'Score ' + pct + '%';
  const protoEl = document.createElement('span');
  protoEl.textContent = protoName(f.protocol);
  const timeEl = document.createElement('span');
  timeEl.className = 'a-time';
  const ts = Date.now();
  timeEl.textContent = relTime(ts);
  timeEl.dataset.ts = ts;

  body.append(score, protoEl, timeEl);
  item.append(head, body);

  c.prepend(item);
  while (c.children.length > 25) c.removeChild(c.lastChild);

  alertCount++;
  $('atkBadge').textContent = alertCount;
}

function clearAlerts() {
  $('alerts').innerHTML = '<div class="empty"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>No threat alerts detected</div>';
  alertCount = 0; $('atkBadge').textContent = '0';
}

setInterval(() => {
  document.querySelectorAll('.a-time').forEach(el => {
    el.textContent = relTime(Number(el.dataset.ts));
  });
}, 15000);

/* Flow Table (Zero Allocation Row Pooling) */
const pool = [];
let tbodyEl = null, emptyRowEl = null;

function initTable() {
  tbodyEl = $('tbody');
  tbodyEl.innerHTML = '';
  emptyRowEl = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = 9;
  td.style.cssText = 'text-align:center;color:var(--dim);padding:2rem';
  td.textContent = 'Start capture to stream flow records...';
  emptyRowEl.appendChild(td);
  tbodyEl.appendChild(emptyRowEl);

  for (let i = 0; i < TABLE_POOL; i++) {
    const tr = document.createElement('tr');
    tr.style.display = 'none';
    for (let c = 0; c < 9; c++) tr.appendChild(document.createElement('td'));
    tbodyEl.appendChild(tr);
    pool.push(tr);
  }
}

function getVal(f, k) {
  switch (k) {
    case 'src':     return f.srcIp + ':' + f.srcPort;
    case 'dst':     return f.dstIp + ':' + f.dstPort;
    case 'proto':   return f.protocol;
    case 'packets': return f.packets;
    case 'bytes':   return f.bytes;
    case 'dur':     return f.duration;
    case 'bps':     return f.bytesPerSecond;
    case 'score':   return f.threat_score;
    default:        return 0;
  }
}

function renderTable() {
  if (!tbodyEl) return;

  let rows = flowList;
  if (attacksOnly) rows = rows.filter(f => f.is_anomaly);
  if (filter) {
    const q = filter.toLowerCase();
    rows = rows.filter(f =>
      f.srcIp.toLowerCase().includes(q) ||
      f.dstIp.toLowerCase().includes(q) ||
      String(f.srcPort).includes(q) ||
      String(f.dstPort).includes(q) ||
      protoName(f.protocol).toLowerCase().includes(q)
    );
  }

  if (rows.length) {
    const dir = sortAsc ? 1 : -1;
    rows = [...rows].sort((a, b) => {
      const va = getVal(a, sortKey), vb = getVal(b, sortKey);
      return va < vb ? -dir : va > vb ? dir : 0;
    });
  }

  document.querySelectorAll('th[data-k]').forEach(th => {
    const active = th.dataset.k === sortKey;
    th.classList.toggle('sorted', active);
    const arr = th.querySelector('.arr');
    if (arr) arr.textContent = active ? (sortAsc ? '^' : 'v') : '^';
  });

  if (!rows.length) {
    emptyRowEl.style.display = '';
    emptyRowEl.firstChild.textContent = flowList.length === 0
      ? 'Start capture to stream flow records...'
      : 'No flows match current filter.';
    for (const tr of pool) tr.style.display = 'none';
    return;
  }
  emptyRowEl.style.display = 'none';

  const n = Math.min(rows.length, TABLE_POOL);
  for (let i = 0; i < n; i++) {
    const f = rows[i];
    const tr = pool[i];
    tr.style.display = '';
    tr.className = f.is_anomaly ? 'attack' : '';

    const c = tr.cells;
    c[0].textContent = `${f.srcIp}:${f.srcPort}`;
    c[1].textContent = `${f.dstIp}:${f.dstPort}`;

    const proto = protoName(f.protocol);
    c[2].textContent = '';
    const sp = document.createElement('span');
    sp.className = 'proto';
    sp.textContent = proto;
    c[2].appendChild(sp);

    c[3].textContent = `${f.packets} (${f.fwd_packets}/${f.bwd_packets})`;
    c[4].textContent = fmtBytes(f.bytes);
    c[5].textContent = f.duration.toFixed(3) + 's';
    c[6].textContent = (f.bytesPerSecond / 1024).toFixed(1) + ' KB/s';

    const pct = (f.threat_score * 100).toFixed(1);
    const color = f.is_anomaly ? '#ef4444' : '#22c55e';
    c[7].textContent = '';
    const wrap = document.createElement('div'); wrap.className = 'score-wrap';
    const bar = document.createElement('div'); bar.className = 'score-bar';
    const fill = document.createElement('div'); fill.className = 'score-fill';
    fill.style.width = pct + '%'; fill.style.background = color;
    bar.appendChild(fill);
    const num = document.createElement('span'); num.className = 'score-num';
    num.style.color = color; num.textContent = pct + '%';
    wrap.append(bar, num);
    c[7].appendChild(wrap);

    c[8].textContent = '';
    const bd = document.createElement('span');
    if (f.is_blocked) {
      bd.className = 'badge atk';
      bd.innerHTML = '🛡️ BLOCKED · ' + ((f.attack_type && f.attack_type !== 'Benign') ? f.attack_type.toUpperCase() : 'ATTACK');
    } else if (f.is_anomaly) {
      bd.className = 'badge atk';
      bd.textContent = (f.attack_type && f.attack_type !== 'Benign') ? f.attack_type.toUpperCase() : 'ATTACK';
    } else {
      bd.className = 'badge ben';
      bd.textContent = 'BENIGN';
    }
    c[8].appendChild(bd);
  }
  for (let i = n; i < TABLE_POOL; i++) pool[i].style.display = 'none';
}

/* Active Mitigation / Auto-Block Engine */
function updateMitigationUI(m) {
  if (!m) return;
  const isEnabled = m.enabled !== false;
  $('autoBlockTxt').textContent = isEnabled ? 'ACTIVE' : 'OFF';
  $('autoBlockBtn').style.background = isEnabled ? 'var(--bad-dim)' : 'var(--panel-elevated)';
  $('autoBlockBtn').style.color = isEnabled ? 'var(--bad)' : 'var(--muted)';
  $('autoBlockBtn').style.borderColor = isEnabled ? 'rgba(239, 68, 68, 0.3)' : 'var(--border)';

  if (document.activeElement !== $('cooldownSelect') && m.cooldown_sec) {
    $('cooldownSelect').value = String(m.cooldown_sec);
  }

  const listEl = $('blockedList');
  const countBadge = $('blockedCountBadge');
  const blocked = m.blocked || [];
  countBadge.textContent = blocked.length + ' BLOCKED';
  countBadge.className = 'pbadge ' + (blocked.length > 0 ? 'red' : '');

  if (!blocked.length) {
    listEl.innerHTML = '<div class="empty" style="padding:0.6rem 0;width:100%"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>No IPs currently blocked &mdash; network traffic clear</div>';
    return;
  }

  listEl.innerHTML = '';
  for (const b of blocked) {
    const card = document.createElement('div');
    card.style.cssText = 'display:inline-flex;align-items:center;gap:8px;padding:4px 9px;border-radius:var(--r-sm);background:var(--bad-dim);border:1px solid rgba(239,68,68,0.3);font-size:0.72rem';

    const ipSpan = document.createElement('span');
    ipSpan.style.cssText = 'font-family:"JetBrains Mono",monospace;font-weight:600;color:var(--bad)';
    ipSpan.textContent = b.ip;

    const rBadge = document.createElement('span');
    rBadge.className = 'badge atk';
    rBadge.style.fontSize = '0.6rem';
    rBadge.textContent = (b.reason || 'THREAT').toUpperCase();

    const tSpan = document.createElement('span');
    tSpan.style.cssText = 'color:var(--muted);font-size:0.68rem';
    tSpan.textContent = '⏱ ' + b.remaining_sec + 's';

    const unbtn = document.createElement('button');
    unbtn.className = 'btn-ghost';
    unbtn.style.cssText = 'padding:1px 6px;font-size:0.62rem';
    unbtn.textContent = 'UNBLOCK';
    unbtn.onclick = () => unblockIP(b.ip);

    card.append(ipSpan, rBadge, tSpan);
    if (b.is_whitelisted) {
      const wl = document.createElement('span');
      wl.style.cssText = 'font-size:0.6rem;color:var(--dim)';
      wl.textContent = '(SIM DROP)';
      card.appendChild(wl);
    }
    card.appendChild(unbtn);
    listEl.appendChild(card);
  }
}

async function unblockIP(ip) {
  try {
    await fetch('/api/mitigation/unblock' + (TOKEN ? '?token=' + TOKEN : ''), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {}) },
      body: JSON.stringify({ ip })
    });
  } catch (err) {
    console.error('Failed to unblock IP:', err);
  }
}

$('autoBlockBtn').onclick = async () => {
  const current = $('autoBlockTxt').textContent === 'ACTIVE';
  const next = !current;
  try {
    await fetch('/api/mitigation/config' + (TOKEN ? '?token=' + TOKEN : ''), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {}) },
      body: JSON.stringify({ enabled: next })
    });
  } catch (err) {
    console.error('Failed to toggle auto block:', err);
  }
};

$('cooldownSelect').onchange = async (e) => {
  const val = parseInt(e.target.value, 10);
  try {
    await fetch('/api/mitigation/config' + (TOKEN ? '?token=' + TOKEN : ''), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {}) },
      body: JSON.stringify({ cooldown_sec: val })
    });
  } catch (err) {
    console.error('Failed to update cooldown:', err);
  }
};

/* Controls & Keyboard */
$('startBtn').onclick = startCapture;
$('stopBtn').onclick  = stopCapture;
$('clearAlerts').onclick = clearAlerts;

$('thr').oninput = e => {
  const v = parseFloat(e.target.value);
  $('thrVal').textContent = v.toFixed(2);
  currentThreshold = v;
  $('thrBadge').textContent = 'thr ' + v.toFixed(2);
  cThreat.draw();
};

$('search').oninput = e => { filter = e.target.value.trim(); renderTable(); };
$('atkOnly').onclick = e => {
  attacksOnly = !attacksOnly;
  e.target.classList.toggle('on', attacksOnly);
  renderTable();
};
$('pauseBtn').onclick = e => {
  paused = !paused;
  e.target.classList.toggle('on', paused);
  e.target.textContent = paused ? 'RESUME' : 'PAUSE';
};
$('exportBtn').onclick = () => {
  const cols = ['startTimeUnixMs','srcIp','srcPort','dstIp','dstPort','protocol',
                'duration','packets','bytes','packetsPerSecond','bytesPerSecond',
                'averagePacketSize','synCount','ackCount','finCount','rstCount',
                'pshCount','urgCount','fwd_packets','fwd_bytes','bwd_packets','bwd_bytes',
                'threat_score','is_anomaly','attack_type'];
  const csv = [cols.join(',')].concat(
    flowList.map(r => cols.map(c => {
      const v = r[c];
      return typeof v === 'string' && v.includes(',') ? '"' + v + '"' : v;
    }).join(','))
  ).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'netsentinel_flows_' + Date.now() + '.csv';
  a.click();
  URL.revokeObjectURL(a.href);
};

document.querySelectorAll('th[data-k]').forEach(th => {
  th.addEventListener('click', () => {
    const k = th.dataset.k;
    if (sortKey === k) sortAsc = !sortAsc;
    else { sortKey = k; sortAsc = false; }
    renderTable();
  });
});

window.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
  if (e.code === 'Space') {
    e.preventDefault();
    if ($('statusPill').classList.contains('ok')) stopCapture(); else startCapture();
  } else if (e.code === 'Escape') {
    clearAlerts();
  }
});

/* System Resource Usage Engine */
let cpuPercent = 0;
let memPercent = 0;

function updateMemoryMetric() {
  if (window.performance && performance.memory) {
    const mem = performance.memory;
    if (mem.jsHeapSizeLimit > 0) {
      memPercent = Math.min(100, Math.max(0, (mem.usedJSHeapSize / mem.jsHeapSizeLimit) * 100));
      return {
        pct: memPercent,
        used: fmtBytes(mem.usedJSHeapSize),
        total: fmtBytes(mem.jsHeapSizeLimit)
      };
    }
  }
  const activeFlowBytes = flowList.length * 1200;
  const bufferBytes = (CHART_WINDOW * 16) + (threatPoints.length * 64);
  const baseline = 16 * 1024 * 1024;
  const estimatedBytes = baseline + activeFlowBytes + bufferBytes;
  const budget = 256 * 1024 * 1024;
  memPercent = Math.min(100, Math.max(1, (estimatedBytes / budget) * 100));
  return {
    pct: memPercent,
    used: fmtBytes(estimatedBytes),
    total: '256 MB'
  };
}

let lastCpuTs = performance.now();
let idleMsAccumulator = 0;
const hasIdleCb = typeof window.requestIdleCallback === 'function';

function scheduleIdlePoll() {
  if (hasIdleCb) {
    window.requestIdleCallback(deadline => {
      idleMsAccumulator += Math.max(0, deadline.timeRemaining());
      scheduleIdlePoll();
    }, { timeout: 150 });
  }
}
if (hasIdleCb) scheduleIdlePoll();

function sampleCpuLoad() {
  const now = performance.now();
  const elapsed = now - lastCpuTs;
  lastCpuTs = now;
  if (elapsed <= 0) return;

  if (hasIdleCb) {
    const idleFraction = Math.min(1, Math.max(0, idleMsAccumulator / elapsed));
    cpuPercent = Math.min(100, Math.max(0.5, (1 - idleFraction) * 100));
    idleMsAccumulator = 0;
  } else {
    const lag = Math.max(0, elapsed - 1000);
    cpuPercent = Math.min(100, Math.max(0.5, (lag / 1000) * 100));
  }
}

/* Periodic Metrics Engine */
setInterval(() => {
  sampleCpuLoad();
  const memData = updateMemoryMetric();

  const cpuStr = cpuPercent.toFixed(1) + '%';
  const memStr = memPercent.toFixed(1) + '%';

  const cpuEl = $('kCpu');
  if (cpuEl) cpuEl.textContent = cpuStr;
  const memEl = $('kMem');
  if (memEl) memEl.textContent = memStr;

  const focusCpu = $('focusCpu');
  if (focusCpu) focusCpu.textContent = cpuStr;
  const focusMem = $('focusMem');
  if (focusMem) focusMem.textContent = memData ? `${memStr} (${memData.used})` : memStr;

  const now = Date.now();
  const dt = (now - lastMsgTs) / 1000;
  if (dt > 0) $('fMsgps').textContent = (msgCount / dt).toFixed(1);
  msgCount = 0; lastMsgTs = now;

  const fps = 1 / Math.max(0.001, (now - lastRenderTs) / 1000);
  if (lastRenderTs) $('fFps').textContent = Math.min(fps, 999).toFixed(0) + ' fps';
  lastRenderTs = now;
}, 1000);

/* Boot */
initTable();
fetchStatus();
connectWS();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def index_page():
    return HTML_CONTENT


@app.get("/api/health")
def health():
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════
#  Entrypoint
# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0 and os.environ.get("NS_NO_SUDO") != "1":
        print("[NetSentinel] Elevating privileges with sudo for raw packet capture…")
        if sys.platform == "darwin":
            print("[NetSentinel] Set NS_NO_SUDO=1 to skip this if /dev/bpf permissions are configured.")
        else:
            print("[NetSentinel] Set NS_NO_SUDO=1 to skip this if you already ran setcap.")
        try:
            os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
        except Exception as exc:  # noqa: BLE001
            print(f"[NetSentinel] Elevation failed: {exc} — continuing unprivileged")

    if not API_TOKEN:
        print(
            f"[NetSentinel] No NS_TOKEN set — dashboard open at http://{HOST}:{PORT}/"
        )
    else:
        print(
            f"[NetSentinel] Bearer auth enabled. Open http://{HOST}:{PORT}/?token={API_TOKEN}"
        )

    uvicorn.run(app, host=HOST, port=PORT, log_level="info", access_log=False)
