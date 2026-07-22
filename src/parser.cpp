#include "../include/parser.hpp"
#include "../include/packet.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void parseEthernet(const u_char* packet, int caplen, PacketInfo& info)
{
    // NOTES: bounds check BEFORE casting — unchanged from before. caplen
    // is how many bytes libpcap actually captured; reading past it is
    // undefined behavior regardless of whether we print or store the result.
    if (caplen < static_cast<int>(sizeof(struct ether_header)))
    {
        return;  // NOTES: info just stays at its default/empty state
    }

    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet);

    // NOTES: this used to be a printf of the MAC bytes. Now it's a copy
    // into the struct — the caller decides later whether/how to display it.
    std::memcpy(info.srcMac, eth->ether_shost, 6);
    std::memcpy(info.dstMac, eth->ether_dhost, 6);

    // NOTES: network byte order still applies the same as before —
    // storing the WRONG (un-converted) value would be just as broken
    // in a struct field as it would in a printed number.
    uint16_t etherType = ntohs(eth->ether_type);
    info.etherType = etherType;

    // NOTES: CRUX — the "EtherType?" decision point, same role as
    // before. The only thing that changed is what happens in each
    // branch: we hand `info` down by reference instead of printing.
    switch (etherType)
    {
        case ETHERTYPE_IP:
            parseIPv4(packet + sizeof(struct ether_header),
                      caplen - static_cast<int>(sizeof(struct ether_header)),
                      info);
            break;

        default:
            // NOTES: ARP / IPv6 / anything else — intentionally left
            // unparsed, per this task's scope. info.etherType still
            // records what it was, even though we stop here.
            break;
    }
}

void parseIPv4(const u_char* packet, int caplen, PacketInfo& info)
{
    if (caplen < static_cast<int>(sizeof(struct ip)))
    {
        return;
    }

    const struct ip* iph = reinterpret_cast<const struct ip*>(packet);

    // NOTES: ip_hl is a WORD count, not a byte count — same reasoning
    // as before, unchanged by this refactor.
    int ipHeaderLen = iph->ip_hl * 4;

    if (caplen < ipHeaderLen)
    {
        return;
    }

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), srcIp, sizeof(srcIp));
    inet_ntop(AF_INET, &(iph->ip_dst), dstIp, sizeof(dstIp));

    // NOTES: hasIPv4 = true is what tells printPacketInfo() later that
    // these fields are real and not just zero-initialized defaults.
    info.hasIPv4  = true;
    info.srcIp    = srcIp;   // std::string copy from the char buffer
    info.dstIp    = dstIp;
    info.protocol = iph->ip_p;
    info.ttl      = iph->ip_ttl;

    const u_char* transportSegment = packet + ipHeaderLen;
    int remaining = caplen - ipHeaderLen;

    // NOTES: CRUX — the "Protocol?" decision point, same role as
    // before. ip_p is a single byte, so still no ntohs() needed here.
    switch (iph->ip_p)
    {
        case IPPROTO_TCP:
            parseTCP(transportSegment, remaining, info);
            break;

        case IPPROTO_UDP:
            parseUDP(transportSegment, remaining, info);
            break;

        case IPPROTO_ICMP:
            parseICMP(transportSegment, remaining, info);
            break;

        default:
            break;
    }
}

void parseTCP(const u_char* packet, int caplen, PacketInfo& info)
{
    if (caplen < static_cast<int>(sizeof(struct tcphdr)))
    {
        return;
    }

    const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(packet);

    info.hasTransport = true;
    info.srcPort = ntohs(tcph->source);
    info.dstPort = ntohs(tcph->dest);

    // NOTES: SCOPE NOTE — TCP flags (SYN/ACK/FIN...) aren't in
    // PacketInfo yet. The task's target field list didn't ask for
    // them, so they're deliberately left out of this pass. Easy to
    // add later: a uint8_t flags bitmask, or individual bool fields,
    // in PacketInfo, filled in right here from tcph->syn/ack/fin/etc.
}

void parseUDP(const u_char* packet, int caplen, PacketInfo& info)
{
    if (caplen < static_cast<int>(sizeof(struct udphdr)))
    {
        return;
    }

    const struct udphdr* udph = reinterpret_cast<const struct udphdr*>(packet);

    info.hasTransport = true;
    info.srcPort = ntohs(udph->source);
    info.dstPort = ntohs(udph->dest);
}

void parseICMP(const u_char* packet, int caplen, PacketInfo& info)
{
    if (caplen < static_cast<int>(sizeof(icmp_header)))
    {
        return;
    }

    const icmp_header* icmph = reinterpret_cast<const icmp_header*>(packet);

    info.hasICMP  = true;
    info.icmpType = icmph->type;
    info.icmpCode = icmph->code;
}
