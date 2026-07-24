#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../include/packet.hpp"

struct FlowKey
{
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol = 0;  // raw IP protocol number (6=TCP, 17=UDP, 1=ICMP...)

                           // Overload the == operator for direct comparison
    bool operator==(const FlowKey& other) const
    {
        return srcIp == other.srcIp && dstIp == other.dstIp && srcPort == other.srcPort
               && dstPort == other.dstPort && protocol == other.protocol;
    }
};

struct Flow
{
    FlowKey key;
    int packet_counter = 0;
};

struct FlowKeyHash
{
    std::size_t operator()(const FlowKey& key) const
    {
        // Combine hashes of all fields
        std::size_t h1 = std::hash<std::string> {}(key.srcIp);
        std::size_t h2 = std::hash<std::string> {}(key.dstIp);
        std::size_t h3 = std::hash<uint16_t> {}(key.srcPort);
        std::size_t h4 = std::hash<uint16_t> {}(key.dstPort);
        std::size_t h5 = std::hash<uint8_t> {}(key.protocol);

        // Combine them (using XOR and bit shifting)
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
};

FlowKey
makeFlowKey(const PacketInfo& info);

void createFlows(const FlowKey& key);

void printFlows();
