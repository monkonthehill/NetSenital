#include <chrono>
#include <cstring>
#include <iostream>
#include <ostream>

#include "../include/flow.hpp"
#include "../include/sniffer.hpp"
#include "../include/extractor.hpp"

int main(int argc, char* argv[]) {
    int        packetCount   = 0;
    int        deviceIndex   = 0;
    int        menuIndex     = 1;

    pcap_t*    captureHandle = nullptr;
    pcap_if_t* allDevices    = nullptr;

    char       errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    // Disable buffering so the dashboard updates immediately.
    std::cout << std::flush;

    // Enumerate available capture devices
    if (pcap_findalldevs(&allDevices, errbuf) == -1) {
        std::cerr << errbuf << '\n';
        return 1;
    }

    pcap_if_t* selectedDevice = nullptr;

    // If an interface name or index was provided via command-line argument:
    if (argc > 1) {
        std::string argStr = argv[1];
        // Check if numeric index
        bool isNumber = true;
        for (char c : argStr) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                isNumber = false;
                break;
            }
        }
        if (isNumber) {
            deviceIndex = std::stoi(argStr);
            selectedDevice = selectNodeByIndex(allDevices, deviceIndex - 1);
        } else {
            // Find by interface name
            for (pcap_if_t* dev = allDevices; dev != nullptr; dev = dev->next) {
                if (argStr == dev->name) {
                    selectedDevice = dev;
                    break;
                }
            }
        }
    }

    if (selectedDevice == nullptr) {
        for (pcap_if_t* dev = allDevices; dev != nullptr; dev = dev->next) {
            std::cout << menuIndex++ << "). " << dev->name << '\n';
            std::cout << (dev->description ? dev->description : "(no description)") << "\n";
        }

        std::cout << "\nSelect capture device: ";
        std::cin >> deviceIndex;

        selectedDevice = selectNodeByIndex(allDevices, deviceIndex - 1);
    }

    if (selectedDevice == nullptr) {
        std::cerr << "Invalid device selection.\n";
        pcap_freealldevs(allDevices);
        return 1;
    }

    std::cout << "\nOpening device: " << selectedDevice->name << '\n';

    // Open capture session with low timeout (25ms) for instantaneous real-time responsiveness
    captureHandle = pcap_open_live(selectedDevice->name, MAXBYTES2CAPTURE,
                                   1,   // Promiscuous mode
                                   25,  // Read timeout (ms)
                                   errbuf);

    if (captureHandle == nullptr) {
        std::cerr << "pcap_open_live failed: " << errbuf << '\n';
        pcap_freealldevs(allDevices);
        return 1;
    }

    // Attempt to configure non-blocking mode for minimal buffering delays
    if (pcap_setnonblock(captureHandle, 0, errbuf) == -1) {
        // Non-fatal warning if unsupported on certain virtual devices
    }

    int linkType = pcap_datalink(captureHandle);

    // Configure sniffer link-layer decoder so macOS loopback (DLT_NULL / DLT_LOOP)
    // vs standard Ethernet / Wi-Fi (DLT_EN10MB) is parsed accurately.
    setLinkLayerType(linkType);

    std::cout << "Link-layer type: " << pcap_datalink_val_to_name(linkType) << "\n\n";

    // Clear terminal before the live dashboard starts.
    std::cout << "\033[H";

    // Start background asynchronous disk writer thread
    start_async_writer();

    // Manual capture loop
    //
    // We intentionally use pcap_next_ex() instead of pcap_loop().
    //
    // pcap_loop() only invokes the callback when packets arrive.
    // During quiet periods there is no opportunity to refresh the
    // dashboard or expire inactive flows.
    //
    // pcap_next_ex() respects the read timeout and returns 0 when
    // no packets arrive, allowing us to perform periodic tasks
    // without relying on incoming traffic.

    struct pcap_pkthdr* packetHeader  = nullptr;
    const u_char*       packetData    = nullptr;

    bool                running       = true;
    int                 captureResult = 0;

    auto                lastHeartbeat = std::chrono::steady_clock::now();

    while (running) {
        int result = pcap_next_ex(captureHandle, &packetHeader, &packetData);

        switch (result) {
            case 1:
                processPackets(reinterpret_cast<u_char*>(&packetCount), packetHeader, packetData);

                break;

            case 0: {
                // Read timeout. No packet arrived, but we can still
                // refresh the dashboard or expire old flows.

                maybeRefreshDisplay(false, packetCount, 0, nullptr);
                maybePruneFlows();

                auto now = std::chrono::steady_clock::now();

                if (std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count() >=
                    5) {
                    std::cerr << "[Heartbeat] Capture active | Packets: " << packetCount << '\n';

                    lastHeartbeat = now;
                }

                break;
            }

            case PCAP_ERROR:
                captureResult = result;
                running       = false;
                break;

            case PCAP_ERROR_BREAK:
                captureResult = result;
                running       = false;
                break;
        }
    }

    // Cleanup

    if (captureResult == PCAP_ERROR) {
        std::cerr << "Capture failed: " << pcap_geterr(captureHandle) << '\n';
    } else if (captureResult == PCAP_ERROR_BREAK) {
        std::cerr << "Capture interrupted.\n";
    }

    pcap_close(captureHandle);
    pcap_freealldevs(allDevices);

    // Stop async disk writer and flush any pending background writes
    stop_async_writer();

    return 0;
}
