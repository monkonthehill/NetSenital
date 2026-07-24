#include "../include/flow.hpp"

#include <ctime>
#include <ctime>    // Required for std::localtime
#include <iomanip>  // Required for std::put_time
#include <iostream>
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

//Flow is the major struct and FlowKey is the sub struct,So we are using vector (temporarly) to store every flow and every time  a new flow comes we make a new entry in ther vector
// std::vector<Flow> flows;
std::unordered_map<FlowKey, Flow, FlowKeyHash> flows;

// We use an unordered_map so flow lookup is O(1) on average.
// The FlowKey identifies a unique network flow, while Flow stores
// the statistics collected for that flow.
//unordered_map requires hash value and the struct FlowKeyHash is used to hash the FlowKey
//my first intution was that unordered_map<key , value> and i think that the value needs to be Flow struct and FlowKey is the one we need to compare
void createFlows(const FlowKey& key, int pac_len, time_t arrival_time)
{
    // Flow newFlow;
    // newFlow.key = key;
    // bool found  = false;
    // for (size_t i = 0; i < flows.size(); ++i)
    // {
    //     if (flows.at(key) == newFlow.key )
    //     {  // This now works thanks to operator==
    //         // Found a match! Update statistics here (e.g., packet counter, byte counter)
    //         flows[i].packet_counter++;
    //         found = true;
    //         break;
    //     }
    // }
    //
    // // 3. If no matching flow was found, add it to our global list
    // if (!found)
    // {
    //     flows.insert({newFlow});
    // }

    auto it = flows.find(key);

    if (it != flows.end())
    {
        it->second.packet_counter++;
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
        newFlow.first_seen     = arrival_time;
        newFlow.last_seen      = arrival_time;
        newFlow.total_bytes += pac_len;
        flows[key] = newFlow;
    }
}

// Helper function to format time_t into a string
std::string formatTime(std::time_t timestamp)
{
    // Convert to local time structure
    std::tm* local_time = std::localtime(&timestamp);

    // Safety check in case localtime returns nullptr
    if (!local_time)
        return "Invalid Time";

    std::ostringstream oss;
    // Format: YYYY-MM-DD HH:MM:SS
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
        double duration = std::difftime(flow.second.last_seen, flow.second.first_seen);

        std::cout << flow.first.srcIp << " : " << flow.first.srcPort << " -> " 
                  << flow.first.dstIp << " : " << flow.first.dstPort
                  << " | Proto: " << static_cast<int>(flow.first.protocol)
                  << " | Packets: " << flow.second.packet_counter << '\n'
                  << "   First Seen: " << formatTime(flow.second.first_seen) << '\n'
                  << "   Last Seen:  " << formatTime(flow.second.last_seen) << '\n'
                  << "   Duration:   " << duration << " sec\n"
                  << "   Avg Packet: " << (flow.second.total_bytes / flow.second.packet_counter) << " bytes\n";

        if (duration > 0)
        {
            std::cout << "   Throughput: " << (flow.second.total_bytes / duration) << " Bps | "
                      << (flow.second.packet_counter / duration) << " pps\n";
        }
        else
        {
            std::cout << "   Throughput: " << flow.second.total_bytes << " Bytes (Single Burst)\n";
        }
        std::cout << "--------------------------------------------------------\n";
    }
    
    // Flush output stream to ensure text renders immediately on-screen
    std::cout << std::flush; 
}
