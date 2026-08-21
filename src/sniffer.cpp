#include "../include/sniffer.hpp"

#include <cctype>
#include <chrono>  // Added for UI refresh timing
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include "../include/flow.hpp"
#include "../include/packet.hpp"
#include "../include/parser.hpp"

// struct pcap_pkthdr {
// 	struct timeval ts;	/* time stamp */
// 	bpf_u_int32 caplen;	/* length of portion present */
// 	bpf_u_int32 len;	/* length of this packet (off wire) */
// };

// NOTES: THIS is the only function that prints parsed-layer info now.
// Everything upstream (parseEthernet -> parseIPv4 -> parseTCP/parseUDP/
// parseICMP) just fills in a PacketInfo and returns silently — see
// packet.hpp and parser.cpp for why that split exists. `static` here
// means this function is only visible inside this .cpp file — nothing
// else needs to call it, so it doesn't need a header declaration.
static void printPacketInfo(const PacketInfo& info)
{
    std::printf(
        "[eth] %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x | etherType 0x%04x\n",
        info.srcMac[0],
        info.srcMac[1],
        info.srcMac[2],
        info.srcMac[3],
        info.srcMac[4],
        info.srcMac[5],
        info.dstMac[0],
        info.dstMac[1],
        info.dstMac[2],
        info.dstMac[3],
        info.dstMac[4],
        info.dstMac[5],
        info.etherType);

    if (!info.hasIPv4 && !info.hasIPv6)
    {
        return;
    }

    if (info.hasIPv6)
    {
        char src6[INET6_ADDRSTRLEN];
        char dst6[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, info.srcIp6, src6, sizeof(src6));
        inet_ntop(AF_INET6, info.dstIp6, dst6, sizeof(dst6));

        std::printf("[ip]  %s -> %s | protocol %u | ttl %u\n", src6, dst6, info.protocol, info.ttl);

        if (info.hasTransport)
        {
            std::printf("[l4]  port %u -> %u\n", info.srcPort, info.dstPort);
        }

        if (info.hasICMPv6)
        {
            std::printf("[icmp] type %u | code %u\n", info.icmpType, info.icmpCode);
        }
        return;
    }

    if (info.hasIPv4)
    {
        in_addr srcAddr, dstAddr;
        srcAddr.s_addr = htonl(info.srcIp);
        dstAddr.s_addr = htonl(info.dstIp);

        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &srcAddr, src, sizeof(src));
        inet_ntop(AF_INET, &dstAddr, dst, sizeof(dst));

        std::printf("[ip]  %s -> %s | protocol %u | ttl %u\n", src, dst, info.protocol, info.ttl);

        if (info.hasTransport)
        {
            std::printf("[l4]  port %u -> %u\n", info.srcPort, info.dstPort);
        }

        if (info.hasICMP)
        {
            std::printf("[icmp] type %u | code %u\n", info.icmpType, info.icmpCode);
        }
        return;
    }
}

// --- LIVE REFRESH THROTTLING ---
// NOTES: this used to be a function-local `static` declared inside
// processPackets(). Moved to file scope because it's shared between two
// call sites: the packet-arrival path (processPackets, below) and the
// capture-timeout path (main.cpp's pcap_next_ex loop). Both need to
// check/update the SAME clock — see maybeRefreshDisplay() for why. Kept
// as file-scope `static` (internal linkage) rather than exposed in the
// header, since only maybeRefreshDisplay() in this file needs to touch it
// directly — main.cpp only ever calls maybeRefreshDisplay(), never this
// variable itself.

static auto last_ui_update = std::chrono::steady_clock::now();

// Refresh interval in milliseconds. Was fixed at 1000ms (1 update/sec)
// via duration_cast<seconds>, which meant "faster than 1/sec" was
// impossible no matter what number you put there. Switched to
// milliseconds so this one constant controls the whole thing:
//   200  -> 5 updates/sec
//   100  -> 10 updates/sec
//   50   -> 20 updates/sec (screen-clear/redraw cost starts to show)
constexpr auto UI_REFRESH_INTERVAL_MS = std::chrono::milliseconds(200);

// NOTES: this is the actual fix for the "freezes for several seconds then
// dumps everything" symptom. Previously this throttle check only ever ran
// inside processPackets(), which pcap_loop() only called when a packet had
// actually arrived. On bursty/quiet traffic (e.g. occasional localhost DNS
// lookups with several seconds of silence between them), nothing was ever
// polling the clock during those quiet gaps, so the screen just sat
// exactly as it was — however long the gap happened to be — even though
// flow tracking (createFlows) kept working correctly the whole time. The
// moment a new packet finally arrived, this check would see that way more
// than one interval had elapsed and dump everything that had silently
// piled up in `flows` in one go. That's not a hang, it's a display that
// could only ever be triggered by traffic.
//
// This is declared WITHOUT `static` (external linkage) and forward
// declared in sniffer.hpp specifically so main.cpp's pcap_next_ex loop can
// also call it on the capture-timeout path (hasPacket == false, nothing
// new arrived, but the flow table can still refresh on schedule) — driving
// the same clock as the packet-arrival path (hasPacket == true, real
// counter/length/info to show), so the display now ticks steadily
// regardless of whether traffic is flowing.
void maybeRefreshDisplay(bool hasPacket, int counterValue, int packetLen, const PacketInfo* info)
{
    auto now = std::chrono::steady_clock::now();

    if (now - last_ui_update < UI_REFRESH_INTERVAL_MS)
    {
        return;
    }

    // Clear the terminal screen and move cursor to home position before redrawing
    std::cout << "\033[2J\033[H" << std::flush;

    // NOTES: printFlows() is a temporary debugging aid. It displays the
    // current flow table so we can verify that packets belonging to the
    // same flow increase the packet counter instead of creating duplicate
    // Flow entries. Fires on every scheduled tick (packet-driven or
    // timeout-driven), not just "after each packet is processed" like the
    // original note said — see the NOTES above this function for why that
    // distinction matters. This can be removed or replaced by proper
    // logging once flow tracking is verified.
    printFlows();

    std::printf("Packet count : %d\n", counterValue);

    if (hasPacket && info != nullptr)
    {
        std::printf("Packet length : %d\n", packetLen);

        printPacketInfo(*info);
    }

    // Flush output stream to avoid terminal rendering delays
    std::cout << std::flush;

   last_ui_update = now;
}

void processPackets(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    //*packet stores the adress of the first byte of contiguous block of bytes.
    // reinterpret_cast is preferred because it makes the conversion explicit.
    // C-style casts can perform multiple kinds of casts implicitly, making
    // code harder to understand and potentially less safe.
    const timeval& arrival_time = pkthdr->ts;

    int* counter = reinterpret_cast<int*>(arg);

    // Track statistics and parse incoming data silently

    ++(*counter);

    // NOTES: this is the actual refactor. Before: parseEthernet() would
    // have printed as it went. Now: it fills `info` and returns silently,
    // and printPacketInfo() is the one deliberate place we look at the
    // result. `info` is fresh (all has* flags false) for every packet.
    PacketInfo info;
    parseEthernet(packet, static_cast<int>(pkthdr->caplen), info);

    // NOTES: after parsing the packet into PacketInfo, we derive a FlowKey
    // (src/dst IP, ports, protocol) that uniquely identifies a network flow.
    // createFlows() searches the existing flow table: if a matching FlowKey is
    // found, it increments that flow's packet counter; otherwise it creates a
    // new Flow and stores it in the global flow list. This lays the foundation
    // for maintaining per-flow statistics instead of treating every packet
    // independently.
    if ((info.hasIPv4 || info.hasIPv6) && (info.hasTransport || info.hasICMP || info.hasICMPv6))
    {
        FlowKey newKey = makeFlowKey(info);

        createFlows(newKey, pkthdr->len, arrival_time);

        // NOTES: throttling itself lives in maybeRefreshDisplay() at file
        // scope, shared with main.cpp's capture-timeout path — see the
        // NOTES above that function and above last_ui_update for why this
        // moved out of an inline check.
        maybeRefreshDisplay(/*hasPacket=*/true, *counter, pkthdr->len, &info);
    }

    maybePruneFlows();
    return;
}

pcap_if_t* selectNodeByIndex(pcap_if_t* head, int targetIndex)
{
    // 1. Handle negative index input
    if (targetIndex < 0)
    {
        return nullptr;
    }

    pcap_if_t* current = head;
    int currentIndex   = 0;

    // 2. Loop until the list ends or we reach the target index
    while (current != nullptr)
    {
        if (currentIndex == targetIndex)
        {
            return current;  // Node selected and returned
        }
        currentIndex++;
        current = current->next;  // Move to the next node
    }

    // 3. Return nullptr if targetIndex is larger than the list size
    return nullptr;
}
