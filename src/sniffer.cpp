#include "../include/sniffer.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
// struct pcap_pkthdr {
// 	struct timeval ts;	/* time stamp */
// 	bpf_u_int32 caplen;	/* length of portion present */
// 	bpf_u_int32 len;	/* length of this packet (off wire) */
// };

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
