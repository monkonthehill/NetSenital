#include "../include/flow.hpp"

#include <iostream>

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

std::vector<Flow> flows;

void createFlows(const FlowKey& key)
{
    Flow newFlow;
    newFlow.key = key;
    bool found  = false;
    for (size_t i = 0; i < flows.size(); ++i)
    {
        if (flows[i].key == newFlow.key)
        {  // This now works thanks to operator==
            // Found a match! Update statistics here (e.g., packet counter, byte counter)
            flows[i].packet_counter++;
            found = true;
            break;
        }
    }

    // 3. If no matching flow was found, add it to our global list
    if (!found)
    {
        flows.push_back(newFlow);
    }
}

void printFlows()
{
    std::cout << "\n===== FLOWS =====\n";

    for (const auto& flow : flows)
    {
        std::cout << flow.key.srcIp << ":" << flow.key.srcPort << " -> " << flow.key.dstIp << ":"
                  << flow.key.dstPort << " Protocol: " << static_cast<int>(flow.key.protocol)
                  << " Packets: " << flow.packet_counter << '\n';
    }

    std::cout << "=================\n";
}
