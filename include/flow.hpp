#pragma once

#include <sys/time.h>
#include <sys/types.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/packet.hpp"

struct FlowKey
{
    bool isIPv6 = false;
    uint32_t srcIp = 0;
    uint32_t dstIp = 0;
    uint8_t srcIp6[16] = {0};
    uint8_t dstIp6[16] = {0};
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t protocol = 0;  // raw IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6...)

    // Overload the == operator for direct comparison
    bool operator==(const FlowKey& other) const
    {
        if (isIPv6 != other.isIPv6 || protocol != other.protocol ||
            srcPort != other.srcPort || dstPort != other.dstPort)
        {
            return false;
        }

        if (isIPv6)
        {
            return std::memcmp(srcIp6, other.srcIp6, 16) == 0 &&
                   std::memcmp(dstIp6, other.dstIp6, 16) == 0;
        }

        return srcIp == other.srcIp && dstIp == other.dstIp;
    }
};

constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;

struct Flow
{
    FlowKey key;
    uint64_t startTimeUnixMs = 0;
    int packet_counter = 0;

    // Length (in bytes) of the most recent packet received in this flow
    int pack_len = 0;

    timeval first_seen{};
    timeval last_seen{};

    // Cumulative sum of payload/packet bytes across the entire lifetime of this flow
    std::uint64_t total_bytes = 0;

    // TCP flag counters
    uint32_t synCount = 0;
    uint32_t ackCount = 0;
    uint32_t finCount = 0;
    uint32_t rstCount = 0;
    uint32_t pshCount = 0;
    uint32_t urgCount = 0;

    void updateTcpFlags(uint8_t flags)
    {
        if (flags & TCP_SYN) synCount++;
        if (flags & TCP_ACK) ackCount++;
        if (flags & TCP_FIN) finCount++;
        if (flags & TCP_RST) rstCount++;
        if (flags & TCP_PSH) pshCount++;
        if (flags & TCP_URG) urgCount++;
    }

    double duration() const
    {
        return (last_seen.tv_sec - first_seen.tv_sec)
             + (last_seen.tv_usec - first_seen.tv_usec) / 1000000.0;
    }
};

namespace flow_detail
{
    template <typename T>
    inline void hash_combine(std::size_t& seed, const T& val)
    {
        std::size_t h = std::hash<T>{}(val);
        seed ^= h + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    }

    inline std::size_t hash_ipv6_bytes(const uint8_t ip6[16])
    {
        uint64_t high = 0, low = 0;
        std::memcpy(&high, ip6, sizeof(uint64_t));
        std::memcpy(&low, ip6 + sizeof(uint64_t), sizeof(uint64_t));
        std::size_t seed = std::hash<uint64_t>{}(high);
        hash_combine(seed, low);
        return seed;
    }
}

struct FlowKeyHash
{
    std::size_t operator()(const FlowKey& key) const
    {
        std::size_t seed = 0;
        flow_detail::hash_combine(seed, key.isIPv6);

        if (key.isIPv6)
        {
            flow_detail::hash_combine(seed, flow_detail::hash_ipv6_bytes(key.srcIp6));
            flow_detail::hash_combine(seed, flow_detail::hash_ipv6_bytes(key.dstIp6));
        }
        else
        {
            flow_detail::hash_combine(seed, key.srcIp);
            flow_detail::hash_combine(seed, key.dstIp);
        }

        flow_detail::hash_combine(seed, key.srcPort);
        flow_detail::hash_combine(seed, key.dstPort);
        flow_detail::hash_combine(seed, key.protocol);

        return seed;
    }
};

extern std::unordered_map<FlowKey, Flow, FlowKeyHash> flows;

FlowKey makeFlowKey(const PacketInfo& info);

std::string ipToString(uint32_t ipNetOrder);
std::string getSrcIpStr(const FlowKey& key);
std::string getDstIpStr(const FlowKey& key);

void createFlows(const FlowKey& key, int pack_len, const timeval& arrival_time, uint8_t tcpFlags = 0);

void delete_flow(std::unordered_map<FlowKey, Flow, FlowKeyHash>& flow_table);

void maybePruneFlows();

void printFlows();

void extract_features(const Flow& newFlow);
