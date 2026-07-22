#pragma once

#include <pcap.h>
#include <cstdint>
#include "packet.hpp"

// NOTES: WHY A CUSTOM ICMP STRUCT
// System ICMP headers (<netinet/ip_icmp.h>) differ between BSD-style
// and Linux-style field names depending on feature-test macros. This
// minimal struct sidesteps that — it's laid out correctly for Echo
// Request/Reply (type 8 / type 0), which is all `ping` ever generates.
struct icmp_header
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

// NOTES: every parse function now takes a PacketInfo& and FILLS it in,
// instead of printing anything itself. Return type stays void — the
// "output" is the side effect of writing into `info`, not stdout.
// Each function still only needs a pointer to the START of its own
// header plus how many bytes remain from there — that design didn't
// change, only what happens with what it finds.
void parseEthernet(const u_char* packet, int caplen, PacketInfo& info);
void parseIPv4(const u_char* packet, int caplen, PacketInfo& info);
void parseTCP(const u_char* packet, int caplen, PacketInfo& info);
void parseUDP(const u_char* packet, int caplen, PacketInfo& info);
void parseICMP(const u_char* packet, int caplen, PacketInfo& info);
