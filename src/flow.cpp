#include "../include/flow.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_map>

#include "../include/packet.hpp"

FlowKey makeFlowKey(const PacketInfo& info) {
    FlowKey key;
    if (info.hasIPv6) {
        key.isIPv6 = true;
        std::memcpy(key.srcIp6, info.srcIp6, 16);
        std::memcpy(key.dstIp6, info.dstIp6, 16);
    } else {
        key.isIPv6 = false;
        key.srcIp  = info.srcIp;
        key.dstIp  = info.dstIp;
    }

    key.dstPort  = info.dstPort;
    key.srcPort  = info.srcPort;
    key.protocol = info.protocol;

    return key;
}

std::string ipToString(uint32_t ipNetOrder) {
    char           buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = ipNetOrder;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

// Byte-order contract:
// PacketInfo and FlowKey store IPv4 addresses in HOST byte order (converted via ntohl() in parser.cpp).
// inet_ntop() expects addresses in NETWORK byte order, so htonl() is explicitly called here.
std::string getSrcIpStr(const FlowKey& key) {
    if (key.isIPv6) {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, key.srcIp6, buf, sizeof(buf));
        return std::string(buf);
    } else {
        return ipToString(htonl(key.srcIp));
    }
}

std::string getDstIpStr(const FlowKey& key) {
    if (key.isIPv6) {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, key.dstIp6, buf, sizeof(buf));
        return std::string(buf);
    } else {
        return ipToString(htonl(key.dstIp));
    }
}

// Flow is the major struct and FlowKey is the sub struct,So we are using vector
// (temporarly) to store every flow and every time a new flow comes we make a new
// entry in the vector
// std::vector<Flow> flows;

// Thread-safety note:
// The `flows` map is owned and accessed strictly by the single main capture thread.
// `processPackets` (packet-arrival callback), `maybeRefreshDisplay` / `printFlows`,
// and `maybePruneFlows` are all synchronously called from the single pcap_next_ex loop
// in main.cpp. No concurrent worker threads touch `flows`. If multi-threaded capture or
// asynchronous UI dispatch is introduced in the future, access to `flows` must be
// synchronized using a mutex or delegated via a thread-safe dispatch queue.
std::unordered_map<FlowKey, Flow, FlowKeyHash> flows;

// We use an unordered_map so flow lookup is O(1) on average.
// The FlowKey identifies a unique network flow, while Flow stores
// the statistics collected for that flow.
// unordered_map requires hash value and the struct FlowKeyHash is used to hash
// the FlowKey
// my first intution was that unordered_map<key , value> and i think that the
// value needs to be Flow struct and FlowKey is the one we need to compare

// Helper: Produces a reverse/mirrored key by swapping source and destination
// endpoints while keeping protocol and isIPv6 identical.
FlowKey mirrorKey(const FlowKey& k) {
    FlowKey m = k;
    if (m.isIPv6) {
        std::swap_ranges(m.srcIp6, m.srcIp6 + 16, m.dstIp6);
    } else {
        std::swap(m.srcIp, m.dstIp);
    }
    std::swap(m.srcPort, m.dstPort);
    return m;
}

// IMPORTANT:
// We now pass the complete timeval instead of only time_t.
// This preserves microsecond precision provided by libpcap.

// NOTE: Direction check compares incoming packet info against the matching flow's
// stored canonical FlowKey (`flow.key`). Returns true if packet matches the original
// flow direction, or false if it is a reply / reverse packet.
bool isForwardPacket(const PacketInfo& info, const Flow& flow) {
    if (flow.key.isIPv6) {
        return std::memcmp(info.srcIp6, flow.key.srcIp6, 16) == 0 &&
               std::memcmp(info.dstIp6, flow.key.dstIp6, 16) == 0 &&
               info.srcPort == flow.key.srcPort &&
               info.dstPort == flow.key.dstPort;
    } else {
        return info.srcIp == flow.key.srcIp && info.dstIp == flow.key.dstIp &&
               info.srcPort == flow.key.srcPort && info.dstPort == flow.key.dstPort;
    }
}

// NOTES: createFlows handles bidirectional flow association. It searches for `key`,
// and if not found, checks `mirrorKey(key)`. If either matches, directional counters
// (fwd_* / bwd_*) are updated accordingly. Otherwise, a new canonical Flow is established.
void createFlows(const FlowKey& key, int pack_len, const timeval& arrival_time,
                 uint8_t tcpFlags) {
    bool isForward = true;
    auto it = flows.find(key);

    if (it == flows.end()) {
        FlowKey revKey = mirrorKey(key);
        it = flows.find(revKey);
        if (it != flows.end()) {
            isForward = false;
        }
    }

    if (it != flows.end()) {
        // Flow exists — update stats
        Flow& flow = it->second;
        flow.packet_counter++;
        flow.total_bytes += pack_len;
        flow.last_seen = arrival_time;
        flow.pack_len  = pack_len;
        flow.updateTcpFlags(tcpFlags);

        // Update directional counters based on whether packet matched canonical or mirror key
        if (isForward) {
            flow.fwd_packets++;
            flow.fwd_bytes += pack_len;
        } else {
            flow.bwd_packets++;
            flow.bwd_bytes += pack_len;
        }
    } else {
        // New flow — create entry with key as canonical
        Flow newFlow;
        newFlow.key             = key;
        newFlow.startTimeUnixMs = arrival_time.tv_sec * 1000 + arrival_time.tv_usec / 1000;
        newFlow.packet_counter  = 1;
        newFlow.total_bytes     = pack_len;
        newFlow.first_seen      = arrival_time;
        newFlow.last_seen       = arrival_time;
        newFlow.pack_len        = pack_len;
        newFlow.updateTcpFlags(tcpFlags);

        // Initialize directional counters (first packet is always forward)
        newFlow.fwd_packets = 1;
        newFlow.bwd_packets = 0;
        newFlow.fwd_bytes   = pack_len;
        newFlow.bwd_bytes   = 0;

        flows.emplace(key, std::move(newFlow));
    }
}

void delete_flow(std::unordered_map<FlowKey, Flow, FlowKeyHash>& flow_table) {
    std::time_t now = std::time(nullptr);

    for (auto it = flow_table.begin(); it != flow_table.end();) {
        // Calculate how long this flow has been idle.
        double idle = std::difftime(now, it->second.last_seen.tv_sec);

        if (idle >= 30) {
            // Note: extract_features() writes the extracted flow record directly to Data/packet_data.csv (void return)
            extract_features(it->second);
            it = flow_table.erase(it);
        } else {
            ++it;
        }
    }
}

static auto    last_prune_time   = std::chrono::steady_clock::now();
constexpr auto PRUNE_INTERVAL_MS = std::chrono::milliseconds(1000);

void           maybePruneFlows() {
    auto now = std::chrono::steady_clock::now();
    if (now - last_prune_time < PRUNE_INTERVAL_MS) {
        return;
    }

    delete_flow(flows);
    last_prune_time = now;
}

// Helper function to format time_t into a string
std::string formatTime(std::time_t timestamp) {
    std::tm* local_time = std::localtime(&timestamp);

    if (!local_time)
        return "Invalid Time";

    std::ostringstream oss;

    oss << std::put_time(local_time, "%Y-%m-%d %H:%M:%S");

    return oss.str();
}

void printFlows() {
    // ANSI Escape Codes:
    // "\033[2J" clears the entire screen.
    // "\033[H" moves the cursor back to the top-left corner (Home).
    std::cout << "\033[2J\033[H";

    std::cout << "===== ACTIVE LIVE FLOWS =====\n";
    std::cout << "Tracked unique streams: " << flows.size() << "\n\n";

    for (const auto& flow : flows) {
        // Use Flow::duration() so microseconds are included.
        double           duration         = flow.second.duration();
        constexpr double MIN_DURATION_SEC = 0.001;  // 1ms floor
        double           rateDuration     = std::max(duration, MIN_DURATION_SEC);

        std::string      srcStr           = getSrcIpStr(flow.first);
        std::string      dstStr           = getDstIpStr(flow.first);

        std::cout << srcStr << ":" << flow.first.srcPort << " -> " << dstStr << ":"
                  << flow.first.dstPort << " | Proto: " << static_cast<int>(flow.first.protocol)
                  << " | Packets: " << flow.second.packet_counter << '\n'
                  << "   Start Time: " << flow.second.startTimeUnixMs << " (Unix ms)\n"
                  << "   First Seen: " << formatTime(flow.second.first_seen.tv_sec) << '\n'
                  << "   Last Seen:  " << formatTime(flow.second.last_seen.tv_sec) << '\n'
                  << "   Duration:   " << duration << " sec\n"
                  << "   Avg Packet: "
                  << static_cast<double>(flow.second.total_bytes) / flow.second.packet_counter
                  << " bytes\n";

        if (flow.first.protocol == 6) {
            std::cout << "   TCP Flags:  SYN=" << flow.second.synCount
                      << " ACK=" << flow.second.ackCount << " FIN=" << flow.second.finCount
                      << " RST=" << flow.second.rstCount << " PSH=" << flow.second.pshCount
                      << " URG=" << flow.second.urgCount << '\n';
        }

        std::cout << "   Throughput: "
                  << static_cast<double>(flow.second.total_bytes) / rateDuration << " Bps | "
                  << static_cast<double>(flow.second.packet_counter) / rateDuration << " pps\n";

        std::cout << "--------------------------------------------------------\n";
    }

    std::cout << std::flush;
}
