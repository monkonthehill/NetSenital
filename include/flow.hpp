#include <sys/time.h>
#include <sys/types.h>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/packet.hpp"

struct FlowKey
{
    uint32_t dstIp;
    uint32_t srcIp;
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
    int pack_len = 0;
    timeval first_seen{};
    timeval last_seen{};

    std::uint64_t total_bytes = 0;

    double duration() const
    {
        return (last_seen.tv_sec - first_seen.tv_sec)
             + (last_seen.tv_usec - first_seen.tv_usec) / 1000000.0;
    }
};

//vibe coded ---->
struct FlowKeyHash
{
    std::size_t operator()(const FlowKey& key) const
    {
        // Combine hashes of all fields
        std::size_t h1 = std::hash<uint32_t>{}(key.srcIp);
        std::size_t h2 = std::hash<u_int32_t> {}(key.dstIp);
        std::size_t h3 = std::hash<uint16_t> {}(key.srcPort);
        std::size_t h4 = std::hash<uint16_t> {}(key.dstPort);
        std::size_t h5 = std::hash<uint8_t> {}(key.protocol);

        // Combine them (using XOR and bit shifting)
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
};

//-------

extern std::unordered_map<FlowKey, Flow, FlowKeyHash> flows;

FlowKey makeFlowKey(const PacketInfo& info);

void createFlows(const FlowKey& key, int pack_len, const timeval& arrival_time);

void delete_flow(std::unordered_map<FlowKey, Flow, FlowKeyHash>& flows);

void printFlows();

void extract_features(const Flow& newFlow);
