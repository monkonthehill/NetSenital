#include "../include/parser.hpp"

#include <cstring>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/types.h>

#include "../include/packet.hpp"

// NOTES: this pass adds IPv6. It needs new fields on PacketInfo (in
// packet.hpp) that this file alone can't provide — add these there:
//   bool    hasIPv6;
//   uint8_t srcIp6[16];
//   uint8_t dstIp6[16];
//   bool    hasICMPv6;
// info.protocol and info.ttl are reused as-is for v6 (see parseIPv6
// below) since ip6_nxt/ip6_hlim are the same conceptual fields as
// ip_p/ip_ttl — no new members needed for those two. parser.hpp also
// needs prototypes added for parseIPv6() and parseICMPv6(), mirroring
// the parseIPv4()/parseICMP() ones already there.

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
    //
    info.etherType = etherType;

    // NOTES: CRUX — the "EtherType?" decision point, same role as
    // before. The only thing that changed is what happens in each
    // branch: we hand `info` down by reference instead of printing.
    switch (etherType)
    {
        case ETHERTYPE_IP:
            parseIPv4(
                packet + sizeof(struct ether_header),
                caplen - static_cast<int>(sizeof(struct ether_header)),
                info);
            break;

        case ETHERTYPE_IPV6:
            // NOTES: same dispatch shape as the IPv4 case above — just
            // a different EtherType value (0x86DD) and a different
            // parse function. The Ethernet layer doesn't care which IP
            // version follows it, so this branch is intentionally
            // symmetric with ETHERTYPE_IP.
            parseIPv6(
                packet + sizeof(struct ether_header),
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

    u_int32_t srcIp /* [INET_ADDRSTRLEN] */;
    u_int32_t dstIp /* [INET_ADDRSTRLEN] */;
    info.srcIp = ntohl(iph->ip_src.s_addr);
    info.dstIp = ntohl(iph->ip_dst.s_addr);

    // NOTES: hasIPv4 = true is what tells printPacketInfo() later that
    // these fields are real and not just zero-initialized defaults.
    info.hasIPv4  = true;
    info.srcIp    = srcIp;
    info.dstIp    = dstIp;
    info.protocol = iph->ip_p;
    info.ttl      = iph->ip_ttl;

    const u_char* transportSegment = packet + ipHeaderLen;
    int remaining                  = caplen - ipHeaderLen;

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

void parseIPv6(const u_char* packet, int caplen, PacketInfo& info)
{
    // NOTES: unlike IPv4's variable ip_hl, the IPv6 base header is
    // ALWAYS 40 bytes — no length field to read out of the header
    // first. sizeof(struct ip6_hdr) does the job directly; there's no
    // "* 4" step because there's nothing variable to multiply.
    if (caplen < static_cast<int>(sizeof(struct ip6_hdr)))
    {
        return;  // NOTES: same empty-info-on-truncation behavior as parseIPv4
    }

    const struct ip6_hdr* iph6 = reinterpret_cast<const struct ip6_hdr*>(packet);

    // NOTES: addresses are 128 bits (16 raw bytes), not a scalar, so
    // there's no ntohl()-equivalent to call — you just copy the bytes
    // as they sit on the wire. Byte order only matters for multi-byte
    // fields libpcap hands you as integers (nxt, hlim below); an
    // address here is already a byte sequence, not a number.
    std::memcpy(info.srcIp6, iph6->ip6_src.s6_addr, 16);
    std::memcpy(info.dstIp6, iph6->ip6_dst.s6_addr, 16);

    // NOTES: ip6_nxt and ip6_hlim are IPv6's equivalents of IPv4's
    // ip_p and ip_ttl — reusing info.protocol/info.ttl instead of
    // adding parallel v6-only fields. Trade-off: any code reading
    // info.protocol later has to know it means "next header" when
    // hasIPv6 is set and "protocol" when hasIPv4 is set. Fine as long
    // as the two hasIPv4/hasIPv6 flags are checked first — same
    // pattern the struct already leans on elsewhere.
    info.hasIPv6  = true;
    info.protocol = iph6->ip6_nxt;
    info.ttl      = iph6->ip6_hlim;

    const u_char* transportSegment = packet + sizeof(struct ip6_hdr);
    int remaining                  = caplen - static_cast<int>(sizeof(struct ip6_hdr));

    // NOTES: CRUX — the "Next Header?" decision point. Looks like
    // parseIPv4's protocol switch, but ip6_nxt carries more possible
    // meanings than ip_p ever does: it can name a transport protocol
    // directly (TCP/UDP/ICMPv6, handled below), OR it can name an
    // IPv6 extension header (Hop-by-Hop Options / Routing / Fragment
    // / Destination Options / AH), which has its own next-header byte
    // pointing further down the chain.
    //
    // SCOPE NOTE: walking that chain (skip each extension header by
    // its own length field, re-check the next ip6_nxt value, repeat)
    // isn't done here. Most captured traffic is plain TCP/UDP over
    // v6 with no extension headers, so this switch only handles the
    // direct case. Packets that use extension headers fall through to
    // default and are left unparsed for now — same spirit as the
    // ARP/other case in parseEthernet's switch. To extend later: loop
    // here instead of switching once, consuming each extension
    // header's length before re-reading its "next header" byte.
    switch (iph6->ip6_nxt)
    {
        case IPPROTO_TCP:
            parseTCP(transportSegment, remaining, info);
            break;

        case IPPROTO_UDP:
            parseUDP(transportSegment, remaining, info);
            break;

        case IPPROTO_ICMPV6:
            parseICMPv6(transportSegment, remaining, info);
            break;

        default:
            // NOTES: extension headers (HOPOPTS/ROUTING/FRAGMENT/
            // DSTOPTS/AH/ESP) and anything else land here, unparsed,
            // per the scope note above.
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
    info.hasTransport         = true;
    info.srcPort              = ntohs(tcph->source);
    info.dstPort              = ntohs(tcph->dest);

    // NOTES: SCOPE NOTE — TCP flags (SYN/ACK/FIN...) aren't in
    // PacketInfo yet. The task's target field list didn't ask for
    // them, so they're deliberately left out of this pass. Easy to
    // add later: a uint8_t flags bitmask, or individual bool fields,
    // in PacketInfo, filled in right here from tcph->syn/ack/fin/etc.
    //
    // NOTES: this function is reached identically from both parseIPv4
    // and parseIPv6 — it only ever sees a pointer + remaining length,
    // never the IP version. No v6-specific change needed here, which
    // is exactly why the transport-layer functions stay untouched.
}

void parseUDP(const u_char* packet, int caplen, PacketInfo& info)
{
    if (caplen < static_cast<int>(sizeof(struct udphdr)))
    {
        return;
    }

    const struct udphdr* udph = reinterpret_cast<const struct udphdr*>(packet);

    info.hasTransport = true;
    info.srcPort      = ntohs(udph->source);
    info.dstPort      = ntohs(udph->dest);
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

void parseICMPv6(const u_char* packet, int caplen, PacketInfo& info)
{
    // NOTES: kept as a SEPARATE function from parseICMP rather than
    // folding into it behind an if/else. The first two bytes (type,
    // code) are laid out the same way on the wire in both protocols,
    // so reusing icmp_header for the read is fine — but the type
    // NUMBERS mean different things per protocol (ICMPv6 128/129 are
    // echo request/reply, vs 8/0 for ICMPv4; ICMPv6 also carries
    // Neighbor Discovery messages ICMPv4 has no equivalent for).
    // Keeping hasICMP and hasICMPv6 as distinct flags stops downstream
    // code from reading a v6 type number through v4 assumptions.
    if (caplen < static_cast<int>(sizeof(icmp_header)))
    {
        return;
    }

    const icmp_header* icmp6h = reinterpret_cast<const icmp_header*>(packet);

    info.hasICMPv6 = true;
    info.icmpType  = icmp6h->type;
    info.icmpCode  = icmp6h->code;
}
