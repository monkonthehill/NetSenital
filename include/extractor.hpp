#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include "../include/flow.hpp"

struct FlowFeatures
{
    uint64_t startTimeUnixMs = 0;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t protocol = 0;

    double duration = 0.0;
    uint32_t packets = 0;
    uint64_t bytes = 0;

    double packetsPerSecond = 0.0;
    double bytesPerSecond = 0.0;

    double averagePacketSize = 0.0;

    // TCP flag counters
    uint32_t synCount = 0;
    uint32_t ackCount = 0;
    uint32_t finCount = 0;
    uint32_t rstCount = 0;
    uint32_t pshCount = 0;
    uint32_t urgCount = 0;
};

