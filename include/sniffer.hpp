#pragma once

#include <pcap.h>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
constexpr int MAXBYTES2CAPTURE= 2048;

void processPackets(
    u_char*,
    const pcap_pkthdr*,
    const u_char*
);

pcap_if_t* selectNodeByIndex(
    pcap_if_t* head,
    int targetIndex
);
