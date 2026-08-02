NetSentinel - IPv6 follow-up TODO
==================================

BLOCKING (producing wrong output right now)
--------------------------------------------
[ ] flow.hpp: extend FlowKey to support IPv6 addresses
    - srcIp/dstIp are uint32_t (32-bit) - can't hold a 128-bit v6 address
    - decide the shape before touching makeFlowKey:
        (A) add srcIp6[16]/dstIp6[16] + bool isIPv6 to the same struct
            (simplest, but wastes space per-key and operator==/hash must
            branch on isIPv6, or two different-family flows can compare equal)
        (B) tagged union/variant - more correct, more code
        (C) split into flows4 / flows6 maps with two FlowKey types
            (no wasted space, but duplicates createFlows/printFlows/etc,
            or template them)
    - until fixed: every IPv6 flow with the same protocol+ports collapses
      into ONE shared entry regardless of which hosts are actually talking
      (info.srcIp/dstIp are unset/0 for v6 packets, so they all compare equal)

[ ] flow.cpp: makeFlowKey() - populate v6 fields once FlowKey supports them
    - currently only copies info.srcIp/info.dstIp (v4 fields), never
      info.srcIp6/dstIp6

[ ] flow.hpp: FlowKeyHash - update once v6 fields exist, and fix the combiner
    - current: h1 ^ (h2<<1) ^ (h3<<2) ^ (h4<<3) ^ (h5<<4)
    - small parallel shifts collide easily on structurally similar keys
      (e.g. many flows to one host on sequential ports - a scan pattern,
      which matters for an IDS specifically)
    - replace with a proper hash_combine (fold each field's hash into a
      running seed, not a fixed shift per field)

DESIGN DECISION NEEDED
-----------------------
[ ] Flow directionality: uni- vs bi-directional flows
    - right now A:port -> B:port and B:port -> A:port hash to DIFFERENT keys
    - if feature extraction wants whole-conversation flows (CICFlowMeter-style
      duration/byte counts spanning both directions), normalize src/dst order
      in makeFlowKey (e.g. always store the numerically smaller address as
      srcIp) so both directions land in the same bucket
    - confirm intent before more feature-extraction work builds on top of this

PERFORMANCE
------------
[ ] sniffer.cpp: delete_flow(flows) is called on every packet, unthrottled
    - full map walk + std::time() syscall per packet, not per tick
    - same problem maybeRefreshDisplay() already solved for the UI - apply
      the same fix: gate behind a last_prune_time check (e.g. only actually
      walk the map if >=1s has passed since the last prune)

CORRECTNESS / DISPLAY
-----------------------
[ ] flow.cpp: printFlows() prints raw uint32_t srcIp/dstIp (e.g. 3232235781)
    instead of dotted-decimal
    - route through inet_ntop, same as printPacketInfo already does
    - needs a v6 branch too once FlowKey carries v6 addresses

[ ] sniffer.cpp: "(is IPv6)" / "(is IPv4)" announcement lines have no
    bracket tag, unlike every other log line ([eth]/[ip]/[l4]/[icmp])
    - either drop them (the next [ip] line already says everything) or
      tag them consistently, e.g. "[ip]  (IPv6)"

CLEANUP (no functional impact)
--------------------------------
[ ] sniffer.cpp: processPackets() - unused `int i = 0;`
    (leftover from the old commented-out C-style cast line above it)

[ ] flow.hpp: Flow struct - pack_len vs total_bytes naming is ambiguous
    - clarify with a comment or rename whether pack_len = most recent
      packet's length only, vs total_bytes = running sum across the flow

SCOPE NOTES (deliberately deferred, not bugs)
------------------------------------------------
[ ] parser.cpp: IPv6 extension header chaining unhandled
    - Hop-by-Hop / Routing / Fragment / Destination Options / AH all fall
      to the default case and stay unparsed
    - fine for plain TCP/UDP-over-v6 traffic; revisit if fragmented or
      option-bearing v6 traffic shows up in real captures

[ ] flow.cpp: delete_flow()'s idle check compares the packet's own
    timestamp (last_seen.tv_sec) against wall-clock std::time(nullptr)
    - correct for live capture
    - would be wrong for offline .pcap replay (every flow would read as
      instantly >30s idle and get pruned after its first packet) - only
      matters if replay support is ever added
