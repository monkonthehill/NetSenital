#include <ctime>    // Required for std::localtime
#include "../include/flow.hpp"

struct FlowFeatures
{
    double duration;
    uint32_t packets;
    uint64_t bytes;

    double packetsPerSecond;
    double bytesPerSecond;

    double averagePacketSize;

    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;
};

