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
    bool operator==(const FlowKey& other) const {
      return srcIp    == other.srcIp    &&
        dstIp    == other.dstIp    &&
        srcPort  == other.srcPort  &&
        dstPort  == other.dstPort  &&
        protocol == other.protocol;
    }
};
struct Flow {
  FlowKey key;
  int packet_counter = 0;
};

FlowKey makeFlowKey(const PacketInfo& info);

void createFlows(const FlowKey& key);

void printFlows();

