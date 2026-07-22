#include "../include/sniffer.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>

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

    if (!info.hasIPv4)
    {
        std::printf("[ip]  (not IPv4)\n");
        return;
    }

    std::printf(
        "[ip]  %s -> %s | protocol %u | ttl %u\n",
        info.srcIp.c_str(),
        info.dstIp.c_str(),
        info.protocol,
        info.ttl);

    if (info.hasTransport)
    {
        std::printf("[l4]  port %u -> %u\n", info.srcPort, info.dstPort);
    }

    if (info.hasICMP)
    {
        std::printf("[icmp] type %u | code %u\n", info.icmpType, info.icmpCode);
    }
}

void processPackets(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    //*packet stores the adress of the first byte of contiguous block of bytes.
    // int i = 0 , *counter  = (int *) arg;   in this line we are using c type casting which is not considered safe idk why but it is what it is
    // reinterpret_cast is preferred because it makes the conversion explicit.
    // C-style casts can perform multiple kinds of casts implicitly, making
    // code harder to understand and potentially less safe.
    int i = 0, *counter = reinterpret_cast<int*>(arg);

    std::printf("Packet count : %d\n", ++(*counter));
    std::printf("Packet length : %d\n", pkthdr->len);

    // NOTES: this is the actual refactor. Before: parseEthernet() would
    // have printed as it went. Now: it fills `info` and returns silently,
    // and printPacketInfo() is the one deliberate place we look at the
    // result. `info` is fresh (all has* flags false) for every packet.
    PacketInfo info;
    parseEthernet(packet, static_cast<int>(pkthdr->caplen), info);
    printPacketInfo(info);
    // NOTES: after parsing the packet into PacketInfo, we derive a FlowKey
    // (src/dst IP, ports, protocol) that uniquely identifies a network flow.
    // createFlows() searches the existing flow table: if a matching FlowKey is
    // found, it increments that flow's packet counter; otherwise it creates a
    // new Flow and stores it in the global flow list. This lays the foundation
    // for maintaining per-flow statistics instead of treating every packet
    // independently.
    FlowKey newKey = makeFlowKey(info);
    createFlows(newKey);
    // NOTES: printFlows() is a temporary debugging aid. After each packet is
    // processed, it displays the current flow table so we can verify that
    // packets belonging to the same flow increase the packet counter instead
    // of creating duplicate Flow entries. This can be removed or replaced by
    // proper logging once flow tracking is verified.
    printFlows();
    // NOTES: this raw hex/ASCII payload dump is untouched — it's separate
    // from the layered parser and wasn't part of this task's scope.
    std::printf("Payload:\n");
    for (int i = 0; i < pkthdr->caplen; ++i)
    {
        if (isprint(packet[i]))
        {
            std::printf("%c", packet[i]);
        }
        else
        {
            std::printf(". ");
        }
        if ((i % 16 == 0 && i != 0) || i == pkthdr->caplen - 1)
        {
            std::printf("\n");
        }
    }
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

int main()
{
    int count          = 0;
    int index          = 1;
    int devIndex       = 0;
    pcap_t* descr      = nullptr;
    pcap_if_t* alldevs = nullptr;
    /* pcap_t is an opaque struct representing one active capture session. You never access its fields directly — you only interact with it by passing a pcap_t * to pcap's functions, which use it to both configure the session (filters, buffer settings) and drive it (start capturing, get stats, close). The packet data itself doesn't come from pcap_t — it arrives separately, through the callback's own parameters, each time a packet is captured. */
    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << errbuf << '\n';
    }
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        std::cout << index << "). " << d->name << '\n';
        std::cout << (d->description ? d->description : "(no description)") << '\n';
        index++;
    }
    std::cout << "Enter the index of device you want to moniter : \n";
    std::cin >> devIndex;
    pcap_if_t* selectedDev = selectNodeByIndex(alldevs, devIndex - 1);
    if (selectedDev == nullptr)
    {
        std::cerr << "Invalid device.\n";
        pcap_freealldevs(alldevs);
        return 1;
    };
    std::cout << "Opening device: " << selectedDev->name
              << '\n';  // (also fixes the pointer-print bug from before)

    descr = pcap_open_live(selectedDev->name, MAXBYTES2CAPTURE, 1, 512, errbuf);
    if (descr == nullptr)
    {
        std::cerr << "pcap_open_live failed: " << errbuf << '\n';
        pcap_freealldevs(alldevs);
        return 1;
    }

    int linktype = pcap_datalink(descr);
    std::printf("Link-layer type: %s\n", pcap_datalink_val_to_name(linktype));

    int result = pcap_loop(descr, -1, processPackets, reinterpret_cast<u_char*>(&count));
    if (result == PCAP_ERROR)
    {
        std::cerr << "pcap_loop failed: " << pcap_geterr(descr) << '\n';
    }
    else if (result == PCAP_ERROR_BREAK)
    {
        std::cerr << "pcap_loop was interrupted (pcap_breakloop called)\n";
    }
    pcap_freealldevs(alldevs);  // free only after you're done reading from it
    return 0;
}
