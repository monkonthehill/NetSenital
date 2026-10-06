# NetSentinel - Test Execution & Verification Report

> **Notice:** These test cases and this report are AI generated.

## 1. Executive Summary

This report documents the design, execution, and verification results of the test suite implemented for **NetSentinel**. The suite validates bidirectional flow tracking, key mirroring symmetry, hash collision resistance, direction discrimination, TCP flag accumulation, and feature extraction without modifying any core source code.

- **Status**: All Tests Passed (7 / 7 test suites, 100% success rate)
- **Compiler**: `g++ (GCC) 16.2.1` with `-O2 -Wall -Wextra -Wshadow`
- **Execution Date**: October 2026
- **Test File**: `tests/test_flows.cpp`

---

## 2. Test Suite Overview

| # | Test Suite | Component / Function Under Test | Target Objective | Result |
|---|------------|---------------------------------|------------------|:------:|
| 1 | `test_ipv4_flowkey_and_mirror` | `FlowKey`, `FlowKeyHash`, `mirrorKey()` | Verify IPv4 equality, hash equivalence, and `mirrorKey(mirrorKey(k)) == k` symmetry. | **PASS** |
| 2 | `test_ipv6_flowkey_and_mirror` | `FlowKey`, `FlowKeyHash`, `mirrorKey()` | Verify 128-bit IPv6 byte comparison, hashing, and symmetry under `mirrorKey()`. | **PASS** |
| 3 | `test_hash_collision_resistance` | `FlowKeyHash` (`hash_combine`) | Verify 0 collisions across 1,000 sequential port scan destination ports (`10.0.0.1:50000 -> 10.0.0.2:1..1000`). | **PASS** |
| 4 | `test_ipv4_bidirectional_aggregation` | `createFlows()`, `isForwardPacket()` | Verify reverse packets match existing canonical flow, update `bwd_packets`/`bwd_bytes` without duplicate entry creation, and identify packet direction. | **PASS** |
| 5 | `test_ipv6_bidirectional_aggregation` | `createFlows()`, IPv6 bidirectional tracking | Verify IPv6 bidirectional packet pairing, forward/backward bucket accumulation, and flow table uniqueness. | **PASS** |
| 6 | `test_duration_and_rate_floor` | `Flow::duration()`, rate denominator floor | Verify sub-millisecond and zero-duration packets are floored to 1ms (`0.001s`), preventing `inf` and `NaN` rates. | **PASS** |
| 7 | `test_feature_extraction_directional` | `extract_features()`, `FlowFeatures` | Verify extracted directional metrics (`fwd_packets`, `fwd_bytes`, `bwd_packets`, `bwd_bytes`) and TCP flags accurately transfer to CSV dataset schema. | **PASS** |

---

## 3. Detailed Verification Results

### Test 1: IPv4 FlowKey Equality & Mirror Symmetry
- **Input**: `192.168.1.1:54321 -> 8.8.8.8:53 (UDP)`
- **Verifications**:
  - `k1 == k2` and `hasher(k1) == hasher(k2)`.
  - `mirrorKey(k1)` swapped `srcIp <-> dstIp` and `srcPort <-> dstPort` while preserving `protocol` and `isIPv6 = false`.
  - `mirrorKey(mirrorKey(k1)) == k1` and double-mirrored hash matches initial hash.

### Test 2: IPv6 FlowKey Equality & Mirror Symmetry
- **Input**: Dual 16-byte IPv6 addresses `2001:db8::1:443 -> 2001:db8::2:60000 (TCP)`
- **Verifications**:
  - `std::memcmp` equality holds across 16-byte arrays.
  - Mirrored key swapped `srcIp6 <-> dstIp6` accurately via `std::swap_ranges`.
  - Inverted key restored original state identically.

### Test 3: Hash Collision Resistance
- **Input**: Fixed source endpoint with 1,000 sequential destination ports (`1..1000`).
- **Verifications**:
  - `seenHashes` tracked 1,000 unique hash values.
  - Total collisions detected: **0**.

### Test 4 & 5: Bidirectional Aggregation & Direction Detection
- **Input Sequence**:
  1. Packet 1 (Forward SYN, 74 bytes): Client $\rightarrow$ Server.
  2. Packet 2 (Reverse SYN+ACK, 74 bytes): Server $\rightarrow$ Client.
  3. Packet 3 (Forward ACK+PSH+data, 500 bytes): Client $\rightarrow$ Server.
- **Verifications**:
  - Active flow count remained strictly **1** (prevented duplicate reverse stream).
  - Packet 1 established canonical flow: `fwd_packets = 1`, `fwd_bytes = 74`, `bwd_packets = 0`, `bwd_bytes = 0`.
  - Packet 2 matched via `mirrorKey`: `fwd_packets = 1`, `fwd_bytes = 74`, `bwd_packets = 1`, `bwd_bytes = 74`.
  - Packet 3 accumulated forward statistics: `fwd_packets = 2`, `fwd_bytes = 574`, `bwd_packets = 1`, `bwd_bytes = 74`, `total_bytes = 648`.
  - `isForwardPacket(clientPacket, flow)` returned `true`.
  - `isForwardPacket(serverPacket, flow)` returned `false`.
  - Flags aggregated accurately: `synCount = 2`, `ackCount = 2`, `pshCount = 1`.

### Test 6: Rate Flooring Protection
- **Input**: Identical `first_seen` and `last_seen` timestamps (`duration = 0.0s`).
- **Verifications**:
  - `rateDuration` floored to `0.001s` (1 millisecond).
  - Throughput calculated as `1000.0 PPS` and `100,000.0 BPS`.
  - Guaranteed `std::isinf` and `std::isnan` evaluate to `false`.

### Test 7: Feature Extraction & CSV Export
- **Input**: Multi-packet flow with directional counters (`fwd_packets = 3`, `fwd_bytes = 600`, `bwd_packets = 1`, `bwd_bytes = 200`).
- **Verifications**:
  - `extract_features()` mapped all directional fields into `FlowFeatures`.
  - Row exported to `Data/packet_data.csv` adheres to the updated 22-column format.

---

## 4. How to Run the Tests

To compile and execute the test suite at any time:

```bash
# Compile the test runner
g++ -O2 -Wall -Wextra -Wshadow tests/test_flows.cpp src/flow.cpp src/extractor.cpp -o tests/run_tests

# Run tests
./tests/run_tests

# Clean up test binary
rm -f tests/run_tests
```

### Execution Output:
```text
========================================================
 AI-GENERATED TEST SUITE: NetSentinel Flow Verification
========================================================

[RUN ] test_ipv4_flowkey_and_mirror...
[PASS] test_ipv4_flowkey_and_mirror
[RUN ] test_ipv6_flowkey_and_mirror...
[PASS] test_ipv6_flowkey_and_mirror
[RUN ] test_hash_collision_resistance...
[PASS] test_hash_collision_resistance
[RUN ] test_ipv4_bidirectional_aggregation...
[PASS] test_ipv4_bidirectional_aggregation
[RUN ] test_ipv6_bidirectional_aggregation...
[PASS] test_ipv6_bidirectional_aggregation
[RUN ] test_duration_and_rate_floor...
[PASS] test_duration_and_rate_floor
[RUN ] test_feature_extraction_directional...
[PASS] test_feature_extraction_directional

========================================================
 RESULTS: 7/7 test suites passed (100% success rate)
========================================================
```

---

## 5. Conclusion

The core bidirectional flow tracking and feature extraction logic in `flow.cpp` and `extractor.cpp` is functionally verified. Reverse conversation packets are mapped to canonical flows, directional buckets correctly isolate forward vs backward traffic, and rate denominator floors prevent division-by-zero artifacts.
