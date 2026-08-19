#pragma once
#include <pcap.h>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
constexpr int MAXBYTES2CAPTURE= 2048;

// Forward declaration only — main.cpp passes a PacketInfo* (or nullptr, on
// the capture-timeout path) into maybeRefreshDisplay() below but never
// dereferences it directly, so a full definition isn't needed in this
// header. Keeps sniffer.hpp from having to pull in packet.hpp just for a
// pointer parameter.
struct PacketInfo;

void processPackets(
    u_char*,
    const pcap_pkthdr*,
    const u_char* packet
);
pcap_if_t* selectNodeByIndex(
    pcap_if_t* head,
    int targetIndex
);

// NOTES: exposed so main.cpp's capture loop can drive the throttled redraw
// on BOTH code paths — when a real packet arrives (hasPacket = true, with
// counterValue/packetLen/info to show) and when pcap_next_ex() times out
// with no packet available (hasPacket = false, info = nullptr). Without
// this being callable from main.cpp too, the display could only ever be
// checked/redrawn in response to a packet actually arriving, which is what
// caused the "freezes for several seconds on quiet traffic" issue. See the
// full explanation in sniffer.cpp above this function's definition.
void maybeRefreshDisplay(bool hasPacket, int counterValue, int packetLen, const PacketInfo* info);
