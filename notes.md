# NetSentinel - Development Notes & Decision Log

## 1. Overview of Completed Work

This document summarizes the architectural updates, bug fixes, performance optimizations, and design decisions implemented across the NetSentinel network intrusion detection system (NIDS).

---

## 2. Key Design Decisions

### A. FlowKey IPv6 Representation (Decision: Flat struct with `isIPv6` discriminator)
- **Problem**: `FlowKey` previously used 32-bit `uint32_t` fields for `srcIp` and `dstIp`, which could not store 128-bit IPv6 addresses. Consequently, all IPv6 flows sharing the same protocol and ports collapsed into a single entry (`0.0.0.0:port -> 0.0.0.0:port`).
- **Options Considered**:
  1. *Flat struct with `srcIp6[16]`/`dstIp6[16]` and `bool isIPv6`* (Selected).
  2. *Tagged union/variant* (Higher boilerplate and accessor complexity).
  3. *Separate maps for IPv4 and IPv6* (Duplicates flow lookup, pruning, feature extraction, and dashboard logic).
- **Rationale**: Adding `bool isIPv6` alongside `srcIp6[16]` and `dstIp6[16]` provides direct byte-level compatibility with `PacketInfo`, avoids heap allocations, keeps `operator==` branch-efficient, and preserves a single unified flow tracking table.

### B. FlowKey Hashing & Collision Mitigation
- **Problem**: The previous hash implementation used fixed bit-shifts: `h1 ^ (h2<<1) ^ (h3<<2) ^ (h4<<3) ^ (h5<<4)`. In IDS scenarios where port scans occur across sequential ports (e.g. `10.0.0.1:50000 -> 10.0.0.2:1..1000`), small fixed shifts create high collision rates.
- **Solution**: Implemented a Boost-style `hash_combine` algorithm:
  $$\text{seed} \leftarrow \text{seed} \oplus (h + \text{0x9e3779b97f4a7c15ULL} + (\text{seed} \ll 6) + (\text{seed} \gg 2))$$
  For IPv6, the 16-byte address is folded into 64-bit segments and combined into the seed.
- **Result**: Tested against 1,000 sequential destination ports with 0 hash collisions.

### C. Flow Directionality (Decision: Standard Unidirectional 5-Tuple Flows)
- **Analysis**: Unidirectional 5-tuple flows (`srcIp:srcPort -> dstIp:dstPort`) are the industry standard for NetFlow v5/v9 and IPFIX.
- **Rationale**: Keeping client-to-server and server-to-client flows separate preserves accurate per-direction metrics (packets per second, bytes per second, packet size distributions) and prevents ambiguity in port roles. This directly prepares the engine for Phase 2's bi-directional forward/backward feature aggregation.

---

## 3. Bug Fixes & Correctness Improvements

1. **IPv4 Parser Uninitialized Stack Variable Bug (`src/parser.cpp`)**:
   - In `parseIPv4()`, local uninitialized variables `u_int32_t srcIp` and `u_int32_t dstIp` were previously declared and assigned back into `info.srcIp` and `info.dstIp`, overwriting the real addresses with garbage values.
   - Fixed by removing the unused stack variables and directly storing `ntohl(iph->ip_src.s_addr)` and `ntohl(iph->ip_dst.s_addr)`.

2. **Flow Key Population for IPv6 (`src/flow.cpp`)**:
   - `makeFlowKey()` now inspects `info.hasIPv6` and copies the 16-byte `srcIp6` and `dstIp6` arrays or IPv4 addresses accordingly.

3. **Flow IP Formatting (`src/flow.cpp`)**:
   - `printFlows()` previously dumped raw 32-bit integers (`3232235781`).
   - Updated to use `inet_ntop(AF_INET, ...)` for dotted-decimal IPv4 representation (`192.168.1.100`) and `inet_ntop(AF_INET6, ...)` for standard hex-colon IPv6 notation (`2001:db8::1`).

4. **ICMP / ICMPv6 Flow Tracking (`src/sniffer.cpp`)**:
   - Updated condition in `processPackets()` from `info.hasTransport` to `(info.hasTransport || info.hasICMP || info.hasICMPv6)` so ICMP flows are tracked and extracted properly.

5. **Log Tag Consistency (`src/sniffer.cpp`)**:
   - Cleaned up untagged `(is IPv6)` / `(is IPv4)` prints in `printPacketInfo()`, ensuring clean `[eth]`, `[ip]`, `[l4]`, and `[icmp]` prefixes.

6. **Compiler Warnings & Cleanup**:
   - Removed unused `int i = 0;` in `src/sniffer.cpp`.
   - Renamed parameter in `delete_flow` to resolve `-Wshadow` warning.
   - Clarified `pack_len` (most recent packet length) vs `total_bytes` (cumulative flow volume) in `include/flow.hpp`.

---

## 4. Performance Optimizations

1. **Throttled Flow Pruning (`maybePruneFlows()`)**:
   - `delete_flow(flows)` was previously executed synchronously on every single captured packet, incurring an O(N) map traversal and a `std::time()` syscall per packet.
   - Created `maybePruneFlows()` which gates flow pruning behind a 1,000ms (1-second) steady-clock throttle.
   - Hooked `maybePruneFlows()` into both the packet processing path (`processPackets`) and the capture timeout path (`main.cpp`), ensuring stale flows expire on schedule even during periods of network inactivity.

---

## 5. Rate Flooring, Timestamps, IP Export & TCP Flag Additions

1. **Elimination of `inf` / Zero-Duration Division**:
   - Rate calculations for PPS and BPS in `extractor.cpp` and `flow.cpp` now floor the denominator using `constexpr double MIN_DURATION_SEC = 0.001;` (1ms floor):
     ```cpp
     double rateDuration = std::max(duration, MIN_DURATION_SEC);
     double packetsPerSecond = packets / rateDuration;
     double bytesPerSecond   = bytes   / rateDuration;
     ```
   - Flow `duration` itself remains exact; only rate denominators are protected against division-by-zero.

2. **Flow Start Timestamp (`startTimeUnixMs`)**:
   - Extracted Unix epoch millisecond timestamp from libpcap's `timeval` on initial packet arrival:
     ```cpp
     flow.startTimeUnixMs = static_cast<uint64_t>(arrival_time.tv_sec) * 1000 + arrival_time.tv_usec / 1000;
     ```
   - Persisted across `Flow`, `FlowFeatures`, and exported as the leading column in `Data/packet_data.csv`.

3. **Source & Destination IP Address String Export**:
   - Added `ipToString(uint32_t)` along with `getSrcIpStr(const FlowKey&)` and `getDstIpStr(const FlowKey&)` supporting both IPv4 (dotted-decimal) and IPv6 (standard hex-colon) formatting via `inet_ntop`.
   - Added `srcIp` and `dstIp` columns to `FlowFeatures` and CSV exports.

4. **TCP Flag Counters & Inspection**:
   - Extracted raw TCP flags (`packet[13]`) in `parseTCP()`.
   - Tracked cumulative counts for `synCount`, `ackCount`, `finCount`, `rstCount`, `pshCount`, and `urgCount` per flow.
   - Propagated flags to live console logging (`[l4] port -> port [flags: SYN ACK ...]`), dashboard statistics, and CSV dataset columns.

---

## 6. Verification & Testing

- Compiled with strict flags: `g++ -O2 -Wall -Wextra -Wshadow ... -lpcap` with **0 errors and 0 warnings**.
- Executed automated unit tests covering:
  - IPv4 `FlowKey` equality, hashing, and dotted-decimal formatting.
  - IPv6 `FlowKey` equality, hashing, and hex-colon formatting.
  - Zero-duration rate flooring (verified `inf`/`nan` eliminated).
  - Accurate start timestamp (`startTimeUnixMs`) calculation.
  - Accumulation of all 6 TCP flags across multiple packets.
  - CSV dataset format and export integrity.
