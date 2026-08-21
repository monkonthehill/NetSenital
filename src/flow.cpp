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

FlowKey makeFlowKey(const PacketInfo& info)
{
    FlowKey key;
    if (info.hasIPv6)
    {
        key.isIPv6 = true;
        std::memcpy(key.srcIp6, info.srcIp6, 16);
        std::memcpy(key.dstIp6, info.dstIp6, 16);
    }
    else
    {
        key.isIPv6 = false;
        key.srcIp  = info.srcIp;
        key.dstIp  = info.dstIp;
    }

    key.dstPort  = info.dstPort;
    key.srcPort  = info.srcPort;
    key.protocol = info.protocol;

    return key;
}

std::string ipToString(uint32_t ipNetOrder)
{
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = ipNetOrder;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::string getSrcIpStr(const FlowKey& key)
{
    if (key.isIPv6)
    {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, key.srcIp6, buf, sizeof(buf));
        return std::string(buf);
    }
    else
    {
        return ipToString(htonl(key.srcIp));
    }
}

std::string getDstIpStr(const FlowKey& key)
{
    if (key.isIPv6)
    {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, key.dstIp6, buf, sizeof(buf));
        return std::string(buf);
    }
    else
    {
        return ipToString(htonl(key.dstIp));
    }
}

// Flow is the major struct and FlowKey is the sub struct,So we are using vector
// (temporarly) to store every flow and every time a new flow comes we make a new
// entry in the vector
// std::vector<Flow> flows;

std::unordered_map<FlowKey, Flow, FlowKeyHash> flows;

// We use an unordered_map so flow lookup is O(1) on average.
// The FlowKey identifies a unique network flow, while Flow stores
// the statistics collected for that flow.
// unordered_map requires hash value and the struct FlowKeyHash is used to hash
// the FlowKey
// my first intution was that unordered_map<key , value> and i think that the
// value needs to be Flow struct and FlowKey is the one we need to compare

// IMPORTANT:
// We now pass the complete timeval instead of only time_t.
// This preserves microsecond precision provided by libpcap.
void createFlows(const FlowKey& key, int pac_len, const timeval& arrival_time, uint8_t tcpFlags)
{
    auto it = flows.find(key);

    if (it != flows.end())
    {
        it->second.packet_counter++;

        // Copy the complete timestamp (tv_sec + tv_usec)
        it->second.last_seen = arrival_time;

        // NOTE: was previously "it->second.total_bytes += it->second.pack_len;"
        // which kept re-adding the FIRST packet's stored length instead of the
        // length of the packet actually arriving now (pac_len). Fixed to use
        // pac_len, and pack_len is refreshed below so it reflects the most
        // recent packet in the flow, not a stale first-packet value.
        it->second.total_bytes += pac_len;
        it->second.pack_len = pac_len;
        it->second.updateTcpFlags(tcpFlags);
    }
    else
    {
        Flow newFlow;
        newFlow.key = key;
        newFlow.startTimeUnixMs = static_cast<uint64_t>(arrival_time.tv_sec) * 1000
                                + arrival_time.tv_usec / 1000;
        newFlow.packet_counter = 1;
        newFlow.pack_len       = pac_len;
        newFlow.total_bytes    = pac_len;

        // Copy the complete timestamp instead of only tv_sec.
        newFlow.first_seen = arrival_time;
        newFlow.last_seen  = arrival_time;
        newFlow.updateTcpFlags(tcpFlags);

        flows[key] = newFlow;

        // Don't extract features here.
        // A newly created flow usually has only one packet,
        // so duration will almost always be zero.
    }
}

void delete_flow(std::unordered_map<FlowKey, Flow, FlowKeyHash>& flow_table)
{
    std::time_t now = std::time(nullptr);

    for (auto it = flow_table.begin(); it != flow_table.end();)
    {
        // Calculate how long this flow has been idle.
        double idle = std::difftime(now, it->second.last_seen.tv_sec);

        if (idle >= 30)
        {
            extract_features(it->second);
            it = flow_table.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

static auto last_prune_time = std::chrono::steady_clock::now();
constexpr auto PRUNE_INTERVAL_MS = std::chrono::milliseconds(1000);

void maybePruneFlows()
{
    auto now = std::chrono::steady_clock::now();
    if (now - last_prune_time < PRUNE_INTERVAL_MS)
    {
        return;
    }

    delete_flow(flows);
    last_prune_time = now;
}

// Helper function to format time_t into a string
std::string formatTime(std::time_t timestamp)
{
    std::tm* local_time = std::localtime(&timestamp);

    if (!local_time)
        return "Invalid Time";

    std::ostringstream oss;

    oss << std::put_time(local_time, "%Y-%m-%d %H:%M:%S");

    return oss.str();
}

void printFlows()
{
    // ANSI Escape Codes:
    // "\033[2J" clears the entire screen.
    // "\033[H" moves the cursor back to the top-left corner (Home).
    std::cout << "\033[2J\033[H";

    std::cout << "===== ACTIVE LIVE FLOWS =====\n";
    std::cout << "Tracked unique streams: " << flows.size() << "\n\n";

    for (const auto& flow : flows)
    {
        // Use Flow::duration() so microseconds are included.
        double duration = flow.second.duration();
        constexpr double MIN_DURATION_SEC = 0.001; // 1ms floor
        double rateDuration = std::max(duration, MIN_DURATION_SEC);

        std::string srcStr = getSrcIpStr(flow.first);
        std::string dstStr = getDstIpStr(flow.first);

        std::cout << srcStr << ":" << flow.first.srcPort << " -> " << dstStr << ":" << flow.first.dstPort
                  << " | Proto: " << static_cast<int>(flow.first.protocol)
                  << " | Packets: " << flow.second.packet_counter << '\n'
                  << "   Start Time: " << flow.second.startTimeUnixMs << " (Unix ms)\n"
                  << "   First Seen: " << formatTime(flow.second.first_seen.tv_sec) << '\n'
                  << "   Last Seen:  " << formatTime(flow.second.last_seen.tv_sec) << '\n'
                  << "   Duration:   " << duration << " sec\n"
                  << "   Avg Packet: "
                  << static_cast<double>(flow.second.total_bytes) / flow.second.packet_counter
                  << " bytes\n";

        if (flow.first.protocol == 6)
        {
            std::cout << "   TCP Flags:  SYN=" << flow.second.synCount
                      << " ACK=" << flow.second.ackCount
                      << " FIN=" << flow.second.finCount
                      << " RST=" << flow.second.rstCount
                      << " PSH=" << flow.second.pshCount
                      << " URG=" << flow.second.urgCount << '\n';
        }

        std::cout << "   Throughput: "
                  << static_cast<double>(flow.second.total_bytes) / rateDuration << " Bps | "
                  << static_cast<double>(flow.second.packet_counter) / rateDuration << " pps\n";

        std::cout << "--------------------------------------------------------\n";
    }

    std::cout << std::flush;
}
