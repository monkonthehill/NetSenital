#include "../include/flow.hpp"

#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_map>

#include "../include/packet.hpp"

FlowKey makeFlowKey(const PacketInfo& info)
{
    FlowKey key;
    key.srcIp    = info.srcIp;
    key.dstIp    = info.dstIp;
    key.dstPort  = info.dstPort;
    key.srcPort  = info.srcPort;
    key.protocol = info.protocol;

    return key;
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
void createFlows(const FlowKey& key, int pac_len, const timeval& arrival_time)
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
    }
    else
    {
        Flow newFlow;
        newFlow.packet_counter = 1;
        newFlow.key            = key;
        newFlow.pack_len       = pac_len;
        newFlow.total_bytes    = pac_len;

        // Copy the complete timestamp instead of only tv_sec.
        newFlow.first_seen = arrival_time;
        newFlow.last_seen  = arrival_time;

        flows[key] = newFlow;

        // Don't extract features here.
        // A newly created flow usually has only one packet,
        // so duration will almost always be zero.
    }
}

void delete_flow(std::unordered_map<FlowKey, Flow, FlowKeyHash>& flows)
{
    std::time_t now = std::time(nullptr);

    for (auto it = flows.begin(); it != flows.end();)
    {
        // Calculate how long this flow has been idle.
        double idle = std::difftime(now, it->second.last_seen.tv_sec);

        if (idle >= 30)
        {
            extract_features(it->second);
            it = flows.erase(it);
        }
        else
        {
            ++it;
        }
    }
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

        std::cout << flow.first.srcIp << " : " << flow.first.srcPort << " -> " << flow.first.dstIp
                  << " : " << flow.first.dstPort
                  << " | Proto: " << static_cast<int>(flow.first.protocol)
                  << " | Packets: " << flow.second.packet_counter << '\n'
                  << "   First Seen: " << formatTime(flow.second.first_seen.tv_sec) << '\n'
                  << "   Last Seen:  " << formatTime(flow.second.last_seen.tv_sec) << '\n'
                  << "   Duration:   " << duration << " sec\n"
                  << "   Avg Packet: "
                  << static_cast<double>(flow.second.total_bytes) / flow.second.packet_counter
                  << " bytes\n";

        if (duration > 0.0)
        {
            std::cout << "   Throughput: "
                      << static_cast<double>(flow.second.total_bytes) / duration << " Bps | "
                      << static_cast<double>(flow.second.packet_counter) / duration << " pps\n";
        }
        else
        {
            std::cout << "   Throughput: " << flow.second.total_bytes << " Bytes (Single Burst)\n";
        }

        std::cout << "--------------------------------------------------------\n";
    }

    std::cout << std::flush;
}
