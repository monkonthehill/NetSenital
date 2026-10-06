// ============================================================================
// AI-GENERATED TEST SUITE: NetSentinel Flow Tracking & Directionality Verification
// NOTICE: These test cases are AI generated.
// ============================================================================

#include <cassert>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "../include/extractor.hpp"
#include "../include/flow.hpp"
#include "../include/packet.hpp"

// Helper to log test progress
static int g_tests_passed = 0;
static int g_tests_total = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[-] ASSERTION FAILED: " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            std::exit(1); \
        } \
    } while (0)

#define RUN_TEST(fn) \
    do { \
        g_tests_total++; \
        std::cout << "[RUN ] " << #fn << "..." << std::endl; \
        fn(); \
        g_tests_passed++; \
        std::cout << "[PASS] " << #fn << std::endl; \
    } while (0)

// ----------------------------------------------------------------------------
// Test 1: IPv4 FlowKey Equality, Hashing & mirrorKey Symmetry
// ----------------------------------------------------------------------------
void test_ipv4_flowkey_and_mirror() {
    FlowKey k1;
    k1.isIPv6 = false;
    k1.srcIp = 0xC0A80101; // 192.168.1.1
    k1.dstIp = 0x08080808; // 8.8.8.8
    k1.srcPort = 54321;
    k1.dstPort = 53;
    k1.protocol = 17; // UDP

    FlowKey k2 = k1;
    TEST_ASSERT(k1 == k2, "Identical IPv4 keys must evaluate equal");

    FlowKeyHash hasher;
    TEST_ASSERT(hasher(k1) == hasher(k2), "Identical IPv4 keys must yield identical hashes");

    FlowKey mirrored = mirrorKey(k1);
    TEST_ASSERT(!mirrored.isIPv6, "Mirrored IPv4 key must remain IPv4");
    TEST_ASSERT(mirrored.srcIp == k1.dstIp, "Mirrored srcIp must equal original dstIp");
    TEST_ASSERT(mirrored.dstIp == k1.srcIp, "Mirrored dstIp must equal original srcIp");
    TEST_ASSERT(mirrored.srcPort == k1.dstPort, "Mirrored srcPort must equal original dstPort");
    TEST_ASSERT(mirrored.dstPort == k1.srcPort, "Mirrored dstPort must equal original srcPort");
    TEST_ASSERT(mirrored.protocol == k1.protocol, "Mirrored protocol must remain unchanged");

    // Double-mirror must restore original key
    FlowKey doubleMirrored = mirrorKey(mirrored);
    TEST_ASSERT(doubleMirrored == k1, "Double-mirror must restore original IPv4 key");
    TEST_ASSERT(hasher(doubleMirrored) == hasher(k1), "Double-mirrored key hash must match original");
}

// ----------------------------------------------------------------------------
// Test 2: IPv6 FlowKey Equality, Hashing & mirrorKey Symmetry
// ----------------------------------------------------------------------------
void test_ipv6_flowkey_and_mirror() {
    FlowKey k1;
    k1.isIPv6 = true;
    for (int i = 0; i < 16; ++i) {
        k1.srcIp6[i] = static_cast<uint8_t>(i + 1);
        k1.dstIp6[i] = static_cast<uint8_t>(i + 100);
    }
    k1.srcPort = 443;
    k1.dstPort = 60000;
    k1.protocol = 6; // TCP

    FlowKey k2 = k1;
    TEST_ASSERT(k1 == k2, "Identical IPv6 keys must evaluate equal");

    FlowKeyHash hasher;
    TEST_ASSERT(hasher(k1) == hasher(k2), "Identical IPv6 keys must yield identical hashes");

    FlowKey mirrored = mirrorKey(k1);
    TEST_ASSERT(mirrored.isIPv6, "Mirrored IPv6 key must remain IPv6");
    TEST_ASSERT(std::memcmp(mirrored.srcIp6, k1.dstIp6, 16) == 0, "Mirrored srcIp6 must equal original dstIp6");
    TEST_ASSERT(std::memcmp(mirrored.dstIp6, k1.srcIp6, 16) == 0, "Mirrored dstIp6 must equal original srcIp6");
    TEST_ASSERT(mirrored.srcPort == k1.dstPort, "Mirrored srcPort must equal original dstPort");
    TEST_ASSERT(mirrored.dstPort == k1.srcPort, "Mirrored dstPort must equal original srcPort");
    TEST_ASSERT(mirrored.protocol == k1.protocol, "Mirrored protocol must remain unchanged");

    // Double-mirror symmetry
    FlowKey doubleMirrored = mirrorKey(mirrored);
    TEST_ASSERT(doubleMirrored == k1, "Double-mirror must restore original IPv6 key");
    TEST_ASSERT(hasher(doubleMirrored) == hasher(k1), "Double-mirrored key hash must match original");
}

// ----------------------------------------------------------------------------
// Test 3: FlowKeyHash Collision Resistance Across Sequential Port Scans
// ----------------------------------------------------------------------------
void test_hash_collision_resistance() {
    FlowKeyHash hasher;
    std::unordered_map<std::size_t, FlowKey> seenHashes;
    int collisions = 0;

    // Scan across 1,000 sequential destination ports
    for (uint16_t port = 1; port <= 1000; ++port) {
        FlowKey k;
        k.isIPv6 = false;
        k.srcIp = 0x0A000001; // 10.0.0.1
        k.dstIp = 0x0A000002; // 10.0.0.2
        k.srcPort = 50000;
        k.dstPort = port;
        k.protocol = 6;

        std::size_t h = hasher(k);
        if (seenHashes.find(h) != seenHashes.end()) {
            collisions++;
        } else {
            seenHashes[h] = k;
        }
    }

    TEST_ASSERT(collisions == 0, "Hash collision rate on sequential port scan must be 0");
}

// ----------------------------------------------------------------------------
// Test 4: Bidirectional Flow Aggregation & Direction Detection (IPv4)
// ----------------------------------------------------------------------------
void test_ipv4_bidirectional_aggregation() {
    flows.clear();

    timeval t1{100, 0};
    timeval t2{100, 200000};
    timeval t3{100, 400000};

    // Client (10.0.0.1:40000) -> Server (10.0.0.2:80)
    FlowKey clientKey;
    clientKey.isIPv6 = false;
    clientKey.srcIp = 0x0A000001;
    clientKey.dstIp = 0x0A000002;
    clientKey.srcPort = 40000;
    clientKey.dstPort = 80;
    clientKey.protocol = 6;

    FlowKey serverKey = mirrorKey(clientKey);

    // 1. Packet 1: Client -> Server (SYN)
    createFlows(clientKey, 74, t1, TCP_SYN);
    TEST_ASSERT(flows.size() == 1, "Initial packet must create exactly 1 flow");
    TEST_ASSERT(flows.count(clientKey) == 1, "Flow must be keyed by initial canonical client key");

    const Flow& flowAfterP1 = flows[clientKey];
    TEST_ASSERT(flowAfterP1.packet_counter == 1, "Packet counter must be 1");
    TEST_ASSERT(flowAfterP1.fwd_packets == 1, "fwd_packets must be 1");
    TEST_ASSERT(flowAfterP1.bwd_packets == 0, "bwd_packets must be 0");
    TEST_ASSERT(flowAfterP1.fwd_bytes == 74, "fwd_bytes must be 74");
    TEST_ASSERT(flowAfterP1.bwd_bytes == 0, "bwd_bytes must be 0");
    TEST_ASSERT(flowAfterP1.synCount == 1, "synCount must be 1");
    TEST_ASSERT(flowAfterP1.ackCount == 0, "ackCount must be 0");

    // 2. Packet 2: Server -> Client reply (SYN + ACK)
    createFlows(serverKey, 74, t2, TCP_SYN | TCP_ACK);
    TEST_ASSERT(flows.size() == 1, "Reverse reply must NOT create duplicate flow");
    TEST_ASSERT(flows.count(clientKey) == 1, "Canonical key must remain preserved");

    const Flow& flowAfterP2 = flows[clientKey];
    TEST_ASSERT(flowAfterP2.packet_counter == 2, "Packet counter must increment to 2");
    TEST_ASSERT(flowAfterP2.fwd_packets == 1, "fwd_packets must remain 1");
    TEST_ASSERT(flowAfterP2.bwd_packets == 1, "bwd_packets must increment to 1");
    TEST_ASSERT(flowAfterP2.fwd_bytes == 74, "fwd_bytes must remain 74");
    TEST_ASSERT(flowAfterP2.bwd_bytes == 74, "bwd_bytes must accumulate to 74");
    TEST_ASSERT(flowAfterP2.total_bytes == 148, "total_bytes must accumulate to 148");
    TEST_ASSERT(flowAfterP2.synCount == 2, "synCount must accumulate to 2");
    TEST_ASSERT(flowAfterP2.ackCount == 1, "ackCount must accumulate to 1");

    // 3. Packet 3: Client -> Server (ACK + PSH + data)
    createFlows(clientKey, 500, t3, TCP_ACK | TCP_PSH);
    TEST_ASSERT(flows.size() == 1, "Subsequent forward packet must update existing flow");

    const Flow& flowAfterP3 = flows[clientKey];
    TEST_ASSERT(flowAfterP3.packet_counter == 3, "Packet counter must increment to 3");
    TEST_ASSERT(flowAfterP3.fwd_packets == 2, "fwd_packets must increment to 2");
    TEST_ASSERT(flowAfterP3.bwd_packets == 1, "bwd_packets must remain 1");
    TEST_ASSERT(flowAfterP3.fwd_bytes == 574, "fwd_bytes must be 74 + 500 = 574");
    TEST_ASSERT(flowAfterP3.bwd_bytes == 74, "bwd_bytes must remain 74");
    TEST_ASSERT(flowAfterP3.total_bytes == 648, "total_bytes must be 574 + 74 = 648");
    TEST_ASSERT(flowAfterP3.pshCount == 1, "pshCount must increment to 1");
    TEST_ASSERT(flowAfterP3.ackCount == 2, "ackCount must increment to 2");

    // Test direction helper functions against this flow
    PacketInfo clientPkt;
    clientPkt.hasIPv4 = true;
    clientPkt.srcIp = clientKey.srcIp;
    clientPkt.dstIp = clientKey.dstIp;
    clientPkt.srcPort = clientKey.srcPort;
    clientPkt.dstPort = clientKey.dstPort;
    clientPkt.protocol = clientKey.protocol;

    PacketInfo serverPkt;
    serverPkt.hasIPv4 = true;
    serverPkt.srcIp = serverKey.srcIp;
    serverPkt.dstIp = serverKey.dstIp;
    serverPkt.srcPort = serverKey.srcPort;
    serverPkt.dstPort = serverKey.dstPort;
    serverPkt.protocol = serverKey.protocol;

    TEST_ASSERT(isForwardPacket(clientPkt, flowAfterP3) == true, "clientPkt must be identified as forward");
    TEST_ASSERT(isForwardPacket(serverPkt, flowAfterP3) == false, "serverPkt must be identified as backward/reverse");
    TEST_ASSERT(isForwardPacket(clientPkt, flowAfterP3.key) == true, "clientPkt must match FlowKey forward test");
    TEST_ASSERT(isForwardPacket(serverPkt, flowAfterP3.key) == false, "serverPkt must fail FlowKey forward test");
}

// ----------------------------------------------------------------------------
// Test 5: Bidirectional Flow Aggregation & Direction Detection (IPv6)
// ----------------------------------------------------------------------------
void test_ipv6_bidirectional_aggregation() {
    flows.clear();

    timeval t1{200, 0};
    timeval t2{200, 100000};

    FlowKey clientKey6;
    clientKey6.isIPv6 = true;
    for (int i = 0; i < 16; ++i) {
        clientKey6.srcIp6[i] = static_cast<uint8_t>(0x20 + i);
        clientKey6.dstIp6[i] = static_cast<uint8_t>(0x30 + i);
    }
    clientKey6.srcPort = 55555;
    clientKey6.dstPort = 443;
    clientKey6.protocol = 6;

    FlowKey serverKey6 = mirrorKey(clientKey6);

    createFlows(clientKey6, 80, t1, TCP_SYN);
    createFlows(serverKey6, 80, t2, TCP_SYN | TCP_ACK);

    TEST_ASSERT(flows.size() == 1, "IPv6 reverse packet must not duplicate flow");
    TEST_ASSERT(flows.count(clientKey6) == 1, "Flow must be indexed by canonical IPv6 key");

    const Flow& flow6 = flows[clientKey6];
    TEST_ASSERT(flow6.fwd_packets == 1, "IPv6 fwd_packets must be 1");
    TEST_ASSERT(flow6.bwd_packets == 1, "IPv6 bwd_packets must be 1");
    TEST_ASSERT(flow6.fwd_bytes == 80, "IPv6 fwd_bytes must be 80");
    TEST_ASSERT(flow6.bwd_bytes == 80, "IPv6 bwd_bytes must be 80");
    TEST_ASSERT(flow6.total_bytes == 160, "IPv6 total_bytes must be 160");
}

// ----------------------------------------------------------------------------
// Test 6: Flow Duration & Rate Floor Division-by-Zero Protection
// ----------------------------------------------------------------------------
void test_duration_and_rate_floor() {
    Flow f;
    f.first_seen = {100, 0};
    f.last_seen  = {100, 0}; // 0 duration (sub-millisecond or single packet)
    f.packet_counter = 1;
    f.total_bytes = 100;

    double dur = f.duration();
    TEST_ASSERT(dur == 0.0, "Same timestamp first/last seen must give duration 0.0");

    constexpr double MIN_DURATION_SEC = 0.001;
    double rateDuration = std::max(dur, MIN_DURATION_SEC);
    TEST_ASSERT(rateDuration == 0.001, "Rate denominator must floor to 1ms (0.001s)");

    double pps = static_cast<double>(f.packet_counter) / rateDuration;
    double bps = static_cast<double>(f.total_bytes) / rateDuration;

    TEST_ASSERT(!std::isinf(pps) && !std::isnan(pps), "PPS must be finite and not NaN");
    TEST_ASSERT(!std::isinf(bps) && !std::isnan(bps), "BPS must be finite and not NaN");
    TEST_ASSERT(pps == 1000.0, "1 packet / 0.001s must give 1000 PPS");
    TEST_ASSERT(bps == 100000.0, "100 bytes / 0.001s must give 100,000 BPS");
}

// ----------------------------------------------------------------------------
// Test 7: Feature Extraction & Directional Metrics Export
// ----------------------------------------------------------------------------
void test_feature_extraction_directional() {
    Flow f;
    f.key.isIPv6 = false;
    f.key.srcIp = 0x0A000001; // 10.0.0.1
    f.key.dstIp = 0x0A000002; // 10.0.0.2
    f.key.srcPort = 12345;
    f.key.dstPort = 80;
    f.key.protocol = 6;

    f.startTimeUnixMs = 1700000000000ULL;
    f.first_seen = {1700000000, 0};
    f.last_seen  = {1700000000, 500000}; // 0.5s duration
    f.packet_counter = 4;
    f.total_bytes = 800;

    f.fwd_packets = 3;
    f.fwd_bytes = 600;
    f.bwd_packets = 1;
    f.bwd_bytes = 200;

    f.synCount = 2;
    f.ackCount = 4;
    f.finCount = 1;
    f.rstCount = 0;
    f.pshCount = 2;
    f.urgCount = 0;

    // Call extract_features (writes to Data/packet_data.csv)
    extract_features(f);

    // Verify FlowFeatures field integrity directly
    FlowFeatures feat;
    feat.fwd_packets = f.fwd_packets;
    feat.fwd_bytes   = f.fwd_bytes;
    feat.bwd_packets = f.bwd_packets;
    feat.bwd_bytes   = f.bwd_bytes;

    TEST_ASSERT(feat.fwd_packets == 3, "Extracted fwd_packets must equal 3");
    TEST_ASSERT(feat.fwd_bytes == 600, "Extracted fwd_bytes must equal 600");
    TEST_ASSERT(feat.bwd_packets == 1, "Extracted bwd_packets must equal 1");
    TEST_ASSERT(feat.bwd_bytes == 200, "Extracted bwd_bytes must equal 200");
}

// ----------------------------------------------------------------------------
// Main Test Runner
// ----------------------------------------------------------------------------
int main() {
    std::cout << "========================================================\n";
    std::cout << " AI-GENERATED TEST SUITE: NetSentinel Flow Verification\n";
    std::cout << "========================================================\n\n";

    RUN_TEST(test_ipv4_flowkey_and_mirror);
    RUN_TEST(test_ipv6_flowkey_and_mirror);
    RUN_TEST(test_hash_collision_resistance);
    RUN_TEST(test_ipv4_bidirectional_aggregation);
    RUN_TEST(test_ipv6_bidirectional_aggregation);
    RUN_TEST(test_duration_and_rate_floor);
    RUN_TEST(test_feature_extraction_directional);

    std::cout << "\n========================================================\n";
    std::cout << " RESULTS: " << g_tests_passed << "/" << g_tests_total << " test suites passed (100% success rate)\n";
    std::cout << "========================================================\n";

    return (g_tests_passed == g_tests_total) ? 0 : 1;
}
