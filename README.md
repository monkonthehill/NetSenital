<<<<<<< HEAD
# NetSenital
 NetSentinel watches all packets in real time using a C++ program (low-level, fast — directly using your systems strength). It pulls out features like 'how many packets per second? which port? how large?', feeds them into a Python ML model, and the model instantly says: normal or attack.
=======
# NetSentinel

A C++ Network Intrusion Detection System (NIDS) that captures live network traffic using **libpcap**, parses packets, extracts flow features, and will later use a machine learning model to detect malicious traffic.

> **Status:** Work in Progress 🚧

---

## Features

- Live packet capture using libpcap
- Device enumeration
- Interactive network interface selection
- Raw packet inspection
- Packet parsing (coming soon)
- Flow tracking (planned)
- ML-based intrusion detection (planned)
- Prometheus metrics (planned)
- Grafana dashboard (planned)

---

## Project Structure

```text
NetSentinel/
├── images/
│   ├── network_capture_flow.png
│   ├── processpacket_pointer_memory_map.png
│   └── ...
├── include/
│   └── sniffer.hpp
├── src/
│   └── sniffer.cpp
└── README.md
```

---

# How Packet Capture Works

When a packet reaches your computer it first arrives at a **network interface card (NIC)**.

Examples of interfaces:

- `wlan0`
- `eth0`
- `lo`
- `docker0`

Libpcap attaches to one of these interfaces and copies packets before they are processed by higher layers.

![Packet Flow](./images/Network_dia.png)

---

# Packet Capture Pipeline

```
Internet
      │
      ▼
Network Interface
      │
      ▼
Linux Kernel
      │
      ▼
libpcap
      │
      ▼
NetSentinel
      │
      ▼
Packet Parser
      │
      ▼
Flow Tracker
      │
      ▼
ML Engine
```

---

# Device Enumeration

The project uses

```cpp
pcap_findalldevs()
```

to enumerate every network interface available on the operating system.

Internally, this function allocates a linked list.

```
alldevs
   │
   ▼
+---------+
| lo      |
| next ---+-------->
+---------+

          +---------+
          | wlan0   |
          | next ---+-------->
          +---------+

                    +---------+
                    | eth0    |
                    | next=NULL
                    +---------+
```

Each node is represented by `pcap_if_t`.

---

# Selecting an Interface

The linked list is traversed until the requested index is found.

```
head
 │
 ▼
lo → wlan0 → eth0 → nullptr
```

The selected node's `name` is passed to

```cpp
pcap_open_live()
```

---

# Understanding `pcap_t`

`pcap_t` is an **opaque structure** representing an active capture session.

It stores information required by libpcap such as:

- selected interface
- capture state
- filters
- buffer configuration

It **does not contain packet data**.

Each captured packet is delivered separately through the callback.

---

# Understanding the Packet Pointer

The callback receives

```cpp
const u_char* packet
```

This is **not an array**.

It is a pointer to the **first byte** of a contiguous block of memory.

```
packet
  │
  ▼
+------+------+------+------+------+
| 45 | 00 | 00 | 54 | 7A | ...
+------+------+------+------+------+
```

Accessing

```cpp
packet[5]
```

is equivalent to

```cpp
*(packet + 5)
```

---

# Packet Header

Every captured packet also has metadata.

```cpp
struct pcap_pkthdr
{
    timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};
```

`caplen`

Number of bytes actually captured.

`len`

Actual size of the packet on the wire.

Always iterate over

```cpp
caplen
```

when reading `packet`.

---

# Callback Flow

```
pcap_loop()

        │

        ▼

processPackets()

        │

        ├── Increment packet counter

        ├── Read packet header

        ├── Access packet bytes

        └── Parse protocols
```

---

# Memory Layout

![Pointer Memory](./images/processpacket_pointer_memory_map.png)

---

# Current Progress

- [x] Enumerate interfaces
- [x] Select capture device
- [x] Open capture session
- [x] Capture live packets
- [x] Print packet payload
- [ ] Hex dump
- [ ] Ethernet parsing
- [ ] IPv4 parsing
- [ ] TCP parsing
- [ ] UDP parsing
- [ ] Flow tracking
- [ ] Feature extraction
- [ ] Machine Learning integration

---

# Build

```bash
mkdir build
cd build
cmake ..
make
```

---

# References

- libpcap Documentation
- TCP/IP Illustrated — W. Richard Stevens
- Beej's Guide to Network Programming
>>>>>>> master
