#include <chrono>
#include <cstring>
#include <iostream>
#include <ostream>

#include "../include/sniffer.hpp"

int main()
{
    int packetCount = 0;
    int deviceIndex = 0;
    int menuIndex   = 1;

    pcap_t* captureHandle = nullptr;
    pcap_if_t* allDevices = nullptr;

    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    // Disable buffering so the dashboard updates immediately.
    std::cout << std::flush;

    // Enumerate available capture devices
    if (pcap_findalldevs(&allDevices, errbuf) == -1)
    {
        std::cerr << errbuf << '\n';
        return 1;
    }

    for (pcap_if_t* dev = allDevices; dev != nullptr; dev = dev->next)
    {
        std::cout << menuIndex++ << "). " << dev->name << '\n';
        std::cout << (dev->description ? dev->description : "(no description)") << "\n";
    }

    std::cout << "\nSelect capture device: ";
    std::cin >> deviceIndex;

    pcap_if_t* selectedDevice = selectNodeByIndex(allDevices, deviceIndex - 1);

    if (selectedDevice == nullptr)
    {
        std::cerr << "Invalid device selection.\n";
        pcap_freealldevs(allDevices);
        return 1;
    }

    std::cout << "\nOpening device: " << selectedDevice->name << '\n';

    // Open capture session
    captureHandle = pcap_open_live(
        selectedDevice->name,
        MAXBYTES2CAPTURE,
        1,    // Promiscuous mode
        999,  // Read timeout (ms)
        errbuf);

    if (captureHandle == nullptr)
    {
        std::cerr << "pcap_open_live failed: " << errbuf << '\n';
        pcap_freealldevs(allDevices);
        return 1;
    }

    int linkType = pcap_datalink(captureHandle);

    std::cout << "Link-layer type: " << pcap_datalink_val_to_name(linkType) << "\n\n";

    // Clear terminal before the live dashboard starts.
    std::cout << "\033[H";

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

    struct pcap_pkthdr* packetHeader = nullptr;
    const u_char* packetData         = nullptr;

    bool running      = true;
    int captureResult = 0;

    auto lastHeartbeat = std::chrono::steady_clock::now();

    while (running)
    {
        int result = pcap_next_ex(captureHandle, &packetHeader, &packetData);

        switch (result)
        {
            case 1:
                processPackets(reinterpret_cast<u_char*>(&packetCount), packetHeader, packetData);

                break;

            case 0:
            {
                // Read timeout. No packet arrived, but we can still
                // refresh the dashboard or expire old flows.

                maybeRefreshDisplay(false, packetCount, 0, nullptr);

                auto now = std::chrono::steady_clock::now();

                if (std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count()
                    >= 5)
                {
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

    if (captureResult == PCAP_ERROR)
    {
        std::cerr << "Capture failed: " << pcap_geterr(captureHandle) << '\n';
    }
    else if (captureResult == PCAP_ERROR_BREAK)
    {
        std::cerr << "Capture interrupted.\n";
    }

    pcap_close(captureHandle);
    pcap_freealldevs(allDevices);

    return 0;
}
