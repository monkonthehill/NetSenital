#pragma once

#include <cstdint>
#include <string>

// NOTES: THE CORE IDEA OF THIS REFACTOR
// Parsing used to print as it went — every parse function called
// printf() the moment it found something. That meant the ONLY way to
// get packet data out was to read stdout. If you later wanted to save
// packets, track flows, or feed an ML model, you'd have had to
// re-parse the same bytes all over again just to get the data in a
// usable form.
//
// PacketInfo breaks that coupling. From now on, parsing means "fill in
// this struct." What happens to the struct afterward — print it, log
// it, hand it to a flow tracker, feed it to a model — is a completely
// separate concern, and none of those consumers ever need to touch a
// raw byte buffer again.
//
// NOTES: this header intentionally has ZERO printing/I/O dependency
// (no <cstdio>, no <iostream>). That's deliberate — a pure data struct
// should be includable by anything (a parser, an ML pipeline, a unit
// test) without dragging along how it gets displayed.

struct PacketInfo
{
    // --- Ethernet layer --- filled whenever the frame is long enough
    // to contain an Ethernet header at all.
    uint8_t  srcMac[6] = {0};
    uint8_t  dstMac[6] = {0};
    uint16_t etherType = 0;

    // --- IPv4 layer ---
    // NOTES: hasIPv4 exists because not every frame IS IPv4 (it could
    // be ARP, IPv6, or something we don't parse). Without this flag,
    // srcIp/dstIp/ttl would just sit at their zero-initialized
    // defaults with no way to tell "this is genuinely empty" apart
    // from "this layer was never reached." Every optional layer below
    // follows the same has-flag pattern.
    bool        hasIPv4 = false;
    std::string srcIp;
    std::string dstIp;
    uint8_t     protocol = 0;   // raw IP protocol number (6=TCP, 17=UDP, 1=ICMP...)
    uint8_t     ttl = 0;

    // --- Transport layer --- ports  you show me your PacketInfo struonly, shared by TCP and UDP.
    // `protocol` above already tells you which one it was.
    bool     hasTransport = false;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    // --- ICMP ---
    bool    hasICMP = false;
    uint8_t icmpType = 0;
    uint8_t icmpCode = 0;
};
