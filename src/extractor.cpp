#include "../include/extractor.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <cstring>

// struct FlowFeatures {
//     double duration;
//     uint32_t packets;
//     uint64_t bytes;
//     double packetsPerSecond;
//     double bytesPerSecond;
//     double averagePacketSize;
//     uint16_t srcPort;
//     uint16_t dstPort;
//     uint8_t protocol;
// };

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
        csvFile << "duration,packets,bytes,packetsPerSecond,bytesPerSecond,"
                << "averagePacketSize,srcPort,dstPort,protocol\n";
    }
    
    // Write the data row
    csvFile << features.duration << ","
            << features.packets << ","
            << features.bytes << ","
            << features.packetsPerSecond << ","
            << features.bytesPerSecond << ","
            << features.averagePacketSize << ","
            << features.srcPort << ","
            << features.dstPort << ","
            << static_cast<int>(features.protocol)  // Cast to int to print as number, not character
            << "\n";
    
    csvFile.close();
    
    // Optional: Verify if write was successful
    // if (csvFile.good()) {
    //     std::cout << "Features successfully saved to " << filename << std::endl;
    // } else {
    //     std::cerr << "Error occurred while writing to file" << std::endl;
    // }
}

void extract_features(const Flow& flow)
{
    FlowFeatures features;

    double duration = flow.duration();

    features.duration = duration;
    features.packets = flow.packet_counter;
    features.bytes = flow.total_bytes;

    features.averagePacketSize =
        (flow.packet_counter > 0)
            ? static_cast<double>(flow.total_bytes) / flow.packet_counter
            : 0.0;

    if (duration > 0.0)
    {
        features.packetsPerSecond =
            static_cast<double>(flow.packet_counter) / duration;

        features.bytesPerSecond =
            static_cast<double>(flow.total_bytes) / duration;
    }
    else
    {
        features.packetsPerSecond = 0.0;
        features.bytesPerSecond = 0.0;
    }

    features.srcPort = flow.key.srcPort;
    features.dstPort = flow.key.dstPort;
    features.protocol = flow.key.protocol;

    saveFeaturesToCSV(features);
}
