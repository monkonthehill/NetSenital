# NetSentinel - Project TODO & Roadmap

## COMPLETED TASKS (Phase 1 & Follow-Up Enhancements)
------------------------------------------------------
- [x] **flow.hpp**: Extended `FlowKey` to support IPv6 addresses (`isIPv6`, `srcIp6[16]`, `dstIp6[16]`).
- [x] **flow.cpp**: Updated `makeFlowKey()` to populate IPv6 and IPv4 fields accurately from `PacketInfo`.
- [x] **flow.hpp**: Replaced `FlowKeyHash` combiner with Boost-style `hash_combine` algorithm and 128-bit IPv6 folding to eliminate sequential port scan collisions.
- [x] **flow.cpp**: Updated `printFlows()` to render IPv4 in dotted-decimal (`192.168.1.1`) and IPv6 in standard hex-colon (`2001:db8::1`) notation using `inet_ntop`.
- [x] **sniffer.cpp**: Implemented `maybePruneFlows()` throttling to eliminate per-packet map traversals and `std::time()` syscall overhead.
- [x] **sniffer.cpp**: Normalized log output tags and removed redundant untagged `(is IPv4)` / `(is IPv6)` messages.
- [x] **sniffer.cpp**: Enabled flow tracking for ICMP (v4) and ICMPv6 packets.
- [x] **sniffer.cpp**: Cleaned up unused variables (`int i = 0;`).
- [x] **parser.cpp**: Fixed IPv4 uninitialized stack variable bug overwriting `info.srcIp` and `info.dstIp`.
- [x] **flow.hpp**: Documented `pack_len` (most recent packet length) vs `total_bytes` (cumulative flow volume).
- [x] **flow.cpp**: Fixed `-Wshadow` compiler warning in `delete_flow`.
- [x] **extractor.cpp & flow.cpp**: Fixed `inf` / zero-duration rate calculations by flooring rate denominator (`MIN_DURATION_SEC = 0.001`).
- [x] **flow.hpp & flow.cpp**: Captured flow start Unix timestamp in milliseconds (`startTimeUnixMs`) from libpcap `timeval`.
- [x] **flow.hpp & extractor.cpp**: Exported source and destination IP addresses (`srcIp`, `dstIp`) supporting both IPv4 and IPv6 string formats.
- [x] **parser.cpp, flow.hpp, & extractor.cpp**: Implemented TCP flag parsing and counters (`synCount`, `ackCount`, `finCount`, `rstCount`, `pshCount`, `urgCount`) across `PacketInfo`, `Flow`, and CSV export.

---

## PHASE 2: ADVANCED FEATURE EXTRACTION & IPC (In Progress)
------------------------------------------------------------
### Advanced Flow Metrics
- [ ] **Bi-directional Flow Statistics (Forward / Backward)**:
  - Track forward packet/byte counts (`fwd_packets`, `fwd_bytes`) vs backward packet/byte counts (`bwd_packets`, `bwd_bytes`).
  - Calculate forward/backward packet size statistics and header length metrics (CICFlowMeter-compatible).
- [ ] **Inter-Arrival Time (IAT) Calculation**:
  - Compute min, max, mean, and standard deviation of inter-packet arrival times per flow (`fwd_iat_mean`, `bwd_iat_mean`, `flow_iat_std`).
- [ ] **Packet Size Distribution**:
  - Compute payload size variance and standard deviation across flow lifetime.

### Inter-Process Communication
- [ ] **ZeroMQ / Socket Publisher**:
  - Implement a non-blocking publisher to stream expired `FlowFeatures` or live flow metrics to external consumers/Python ML pipelines via IPC/TCP.

---

## PHASE 3: MACHINE LEARNING & ANOMALY DETECTION (Planned)
-----------------------------------------------------------
- [ ] **Offline Training Pipeline (`scripts/train_model.py`)**:
  - Scikit-learn / XGBoost training script parsing exported CSV dataset (`Data/packet_data.csv`).
  - Baseline classification for normal traffic vs port scans, DoS/DDoS, and brute-force patterns.
- [ ] **Real-Time Inference Engine**:
  - Embed lightweight C++ inference runtime or Python sidecar evaluating live flow feature vectors.
  - Generate real-time anomaly scores (0.0 - 1.0) and alert logs.

---

## PHASE 4: MONITORING & VISUALIZATION (Planned)
-------------------------------------------------
- [ ] **Prometheus Metrics Exporter**:
  - Expose active flow count, PPS, BPS, and anomaly counters on `/metrics`.
- [ ] **Grafana Dashboard Configuration**:
  - Pre-configured dashboard templates for real-time traffic visualization and security alerts.

---

## DEFERRED / HARDENING BACKLOG
--------------------------------
- [ ] **parser.cpp: IPv6 Extension Header Chaining**:
  - Parse Hop-by-Hop, Routing, Fragment, and Destination Options headers iteratively to resolve trailing transport payloads.
- [ ] **flow.cpp: Offline PCAP Replay Support**:
  - Decouple flow expiration clock from wall-clock `std::time(nullptr)` to use packet timestamp `pkthdr->ts` when replaying pcap dump files.
