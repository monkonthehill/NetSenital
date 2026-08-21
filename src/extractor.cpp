#include "../include/extractor.hpp"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <cstring>

// Helper function to check if file exists
bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

// Helper function to create directory if it doesn't exist
bool createDirectory(const std::string& path) {
    // Create directory with read/write/execute permissions for owner
    int result = mkdir(path.c_str(), 0755);
    
    if (result == 0) {
        return true; // Directory created successfully
    } else if (errno == EEXIST) {
        return true; // Directory already exists
    } else {
        std::cerr << "Error creating directory: " << strerror(errno) << std::endl;
        return false;
    }
}

void saveFeaturesToCSV(const FlowFeatures& features) {
    // Define the directory and file path
    std::string directory = "Data";
    std::string filename = directory + "/packet_data.csv";
    
    // Create directory if it doesn't exist
    if (!createDirectory(directory)) {
        std::cerr << "Failed to create directory: " << directory << std::endl;
        return;
    }
    
    // Check if file exists to determine if we need to write headers
    bool isNewFile = !fileExists(filename);
    
    // Open file in append mode
    std::ofstream csvFile(filename, std::ios::app);
    
    if (!csvFile.is_open()) {
        std::cerr << "Error: Unable to open file " << filename << std::endl;
        return;
    }
    
    // Write header if this is a new file
    if (isNewFile) {
        csvFile << "startTimeUnixMs,srcIp,dstIp,srcPort,dstPort,protocol,"
                << "duration,packets,bytes,packetsPerSecond,bytesPerSecond,"
                << "averagePacketSize,synCount,ackCount,finCount,rstCount,pshCount,urgCount\n";
    }
    
    // Write the data row
    csvFile << features.startTimeUnixMs << ","
            << features.srcIp << ","
            << features.dstIp << ","
            << features.srcPort << ","
            << features.dstPort << ","
            << static_cast<int>(features.protocol) << ","
            << features.duration << ","
            << features.packets << ","
            << features.bytes << ","
            << features.packetsPerSecond << ","
            << features.bytesPerSecond << ","
            << features.averagePacketSize << ","
            << features.synCount << ","
            << features.ackCount << ","
            << features.finCount << ","
            << features.rstCount << ","
            << features.pshCount << ","
            << features.urgCount
            << "\n";
    
    csvFile.close();
}

void extract_features(const Flow& flow)
{
    FlowFeatures features;

    constexpr double MIN_DURATION_SEC = 0.001; // 1ms floor
    double duration = flow.duration();
    double rateDuration = std::max(duration, MIN_DURATION_SEC);

    features.startTimeUnixMs = flow.startTimeUnixMs;
    features.srcIp = getSrcIpStr(flow.key);
    features.dstIp = getDstIpStr(flow.key);
    features.srcPort = flow.key.srcPort;
    features.dstPort = flow.key.dstPort;
    features.protocol = flow.key.protocol;

    features.duration = duration;
    features.packets = flow.packet_counter;
    features.bytes = flow.total_bytes;

    features.packetsPerSecond = static_cast<double>(flow.packet_counter) / rateDuration;
    features.bytesPerSecond   = static_cast<double>(flow.total_bytes) / rateDuration;

    features.averagePacketSize =
        (flow.packet_counter > 0)
            ? static_cast<double>(flow.total_bytes) / flow.packet_counter
            : 0.0;

    features.synCount = flow.synCount;
    features.ackCount = flow.ackCount;
    features.finCount = flow.finCount;
    features.rstCount = flow.rstCount;
    features.pshCount = flow.pshCount;
    features.urgCount = flow.urgCount;

    saveFeaturesToCSV(features);
}
