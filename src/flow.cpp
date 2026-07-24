#include "../include/flow.hpp"

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
void createFlows(const FlowKey& key)
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
    }
    else
    {
        Flow newFlow;
        newFlow.packet_counter = 1;
        newFlow.key            = key;
        flows[key]             = newFlow;
    }
}

void printFlows()
{
    std::cout << "\n===== FLOWS =====\n";

    for (const auto& flow : flows)
    {
        std::cout << flow.first.srcIp << ":" << flow.first.srcPort << " -> " << flow.first.dstIp
                  << ":" << flow.first.dstPort
                  << " Protocol: " << static_cast<int>(flow.first.protocol)
                  << " Packets: " << flow.second.packet_counter << '\n';
    }

    std::cout << "=================\n";
}
