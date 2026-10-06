#include "../include/extractor.hpp"
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>

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
        return true;  // Directory created successfully
    } else if (errno == EEXIST) {
        return true;  // Directory already exists
    } else {
        std::cerr << "Error creating directory: " << strerror(errno) << std::endl;
        return false;
    }
}

// ----------------------------------------------------------------------------
// ASYNCHRONOUS BACKGROUND I/O WRITER
// Separates disk writes from the high-priority packet capture thread.
// ----------------------------------------------------------------------------
class AsyncFeatureWriter {
private:
    std::queue<FlowFeatures> queue_;
    std::mutex               mtx_;
    std::condition_variable  cv_;
    std::thread              worker_;
    std::atomic<bool>        running_{false};

    void workerLoop() {
        std::string directory = "Data";
        std::string filename  = directory + "/packet_data.csv";

        if (!createDirectory(directory)) {
            std::cerr << "Failed to create directory: " << directory << std::endl;
            return;
        }

        bool isNewFile = !fileExists(filename);
        std::ofstream csvFile(filename, std::ios::app);

        if (!csvFile.is_open()) {
            std::cerr << "Error: Unable to open file " << filename << std::endl;
            return;
        }

        if (isNewFile) {
            csvFile << "startTimeUnixMs,srcIp,dstIp,srcPort,dstPort,protocol,"
                    << "duration,packets,bytes,packetsPerSecond,bytesPerSecond,"
                    << "averagePacketSize,synCount,ackCount,finCount,rstCount,pshCount,urgCount,"
                    << "fwd_packets,fwd_bytes,bwd_packets,bwd_bytes\n";
            csvFile.flush();
        }

        while (true) {
            std::vector<FlowFeatures> batch;
            {
                std::unique_lock<std::mutex> lock(mtx_);
                cv_.wait(lock, [this] {
                    return !queue_.empty() || !running_.load();
                });

                if (!running_.load() && queue_.empty()) {
                    break;
                }

                // Drain all currently enqueued items in a single batch
                while (!queue_.empty()) {
                    batch.push_back(std::move(queue_.front()));
                    queue_.pop();
                }
            }

            // Perform batch disk writes in the background thread (hot capture thread is completely free!)
            for (const auto& features : batch) {
                csvFile << features.startTimeUnixMs << "," << features.srcIp << "," << features.dstIp << ","
                        << features.srcPort << "," << features.dstPort << ","
                        << static_cast<int>(features.protocol) << "," << features.duration << ","
                        << features.packets << "," << features.bytes << "," << features.packetsPerSecond << ","
                        << features.bytesPerSecond << "," << features.averagePacketSize << ","
                        << features.synCount << "," << features.ackCount << "," << features.finCount << ","
                        << features.rstCount << "," << features.pshCount << "," << features.urgCount << ","
                        << features.fwd_packets << "," << features.fwd_bytes << ","
                        << features.bwd_packets << "," << features.bwd_bytes << "\n";
            }
            csvFile.flush();
        }

        csvFile.close();
    }

public:
    AsyncFeatureWriter() = default;

    ~AsyncFeatureWriter() {
        stop();
    }

    void start() {
        if (!running_.load()) {
            running_.store(true);
            worker_ = std::thread(&AsyncFeatureWriter::workerLoop, this);
        }
    }

    void stop() {
        if (running_.load()) {
            running_.store(false);
            cv_.notify_all();
            if (worker_.joinable()) {
                worker_.join();
            }
        }
    }

    void enqueue(FlowFeatures features) {
        if (!running_.load()) {
            // Auto-start worker thread on first enqueue if not explicitly started
            start();
        }
        {
            std::lock_guard<std::mutex> lock(mtx_);
            queue_.push(std::move(features));
        }
        cv_.notify_one();
    }
};

static AsyncFeatureWriter g_async_writer;

void start_async_writer() {
    g_async_writer.start();
}

void stop_async_writer() {
    g_async_writer.stop();
}

void saveFeaturesToCSV(const FlowFeatures& features) {
    // Non-blocking enqueue to background worker
    g_async_writer.enqueue(features);
}

void extract_features(const Flow& flow) {
    FlowFeatures     features;

    constexpr double MIN_DURATION_SEC = 0.001;  // 1ms floor
    double           duration         = flow.duration();
    double           rateDuration     = std::max(duration, MIN_DURATION_SEC);

    features.startTimeUnixMs          = flow.startTimeUnixMs;
    features.srcIp                    = getSrcIpStr(flow.key);
    features.dstIp                    = getDstIpStr(flow.key);
    features.srcPort                  = flow.key.srcPort;
    features.dstPort                  = flow.key.dstPort;
    features.protocol                 = flow.key.protocol;

    features.duration                 = duration;
    features.packets                  = flow.packet_counter;
    features.bytes                    = flow.total_bytes;

    features.fwd_packets              = flow.fwd_packets;
    features.fwd_bytes                = flow.fwd_bytes;
    features.bwd_packets              = flow.bwd_packets;
    features.bwd_bytes                = flow.bwd_bytes;

    features.packetsPerSecond         = static_cast<double>(flow.packet_counter) / rateDuration;
    features.bytesPerSecond           = static_cast<double>(flow.total_bytes) / rateDuration;

    features.averagePacketSize = (flow.packet_counter > 0)
                                     ? static_cast<double>(flow.total_bytes) / flow.packet_counter
                                     : 0.0;

    features.synCount          = flow.synCount;
    features.ackCount          = flow.ackCount;
    features.finCount          = flow.finCount;
    features.rstCount          = flow.rstCount;
    features.pshCount          = flow.pshCount;
    features.urgCount          = flow.urgCount;

    saveFeaturesToCSV(features);
}
