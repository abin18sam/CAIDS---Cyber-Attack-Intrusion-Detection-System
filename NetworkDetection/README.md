# CAIDS — Network Detection / NIDS (Step 1)

Cyber Attacks Intrusion Detection System — first module: **Network Detection**.

```
                 NETWORK DETECTION / NIDS
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
 DATA COLLECTION    PACKET ANALYSIS     FLOW ANALYSIS
 PacketCapture.*     PacketAnalyzer.*    FlowAnalyzer.*
```

## Architecture

| Branch | File(s) | Responsibility |
|---|---|---|
| **Data Collection** | `include/PacketCapture.h`, `src/PacketCapture.cpp` | Wraps libpcap: opens a live interface or offline `.pcap` file, applies a BPF filter, and streams raw frames with minimal overhead (no per-packet heap allocation in the capture path itself). |
| **Packet Analysis** | `include/PacketAnalyzer.h`, `src/PacketAnalyzer.cpp` | Parses Ethernet → IPv4 → TCP/UDP/ICMP headers by hand (bounds-checked, no unsafe struct-casts) into a `PacketInfo`. Runs stateless, single-packet signature checks: malformed headers, NULL/FIN/XMAS scans, invalid TCP flag combinations, suspicious TTL. |
| **Flow Analysis** | `include/FlowAnalyzer.h`, `src/FlowAnalyzer.cpp` | Maintains per-5-tuple flow statistics and per-source sliding-window behavioral state (`unordered_map`, O(1) amortized updates) to catch attacks invisible at the single-packet level: SYN floods and port scans. Idle state is pruned periodically so memory stays bounded on long-running captures. |
| **Orchestration** | `src/main.cpp` | Wires the three branches together, handles CLI args, signal-based shutdown, and prints a run summary (packets seen, drop counts, alerts, active flows). |

## Why this design is efficient

- **Zero-copy capture path**: libpcap hands us a pointer into its own buffer; we don't copy the raw frame.
- **Manual, bounds-checked header parsing** instead of casting the buffer into `struct ip`/`struct tcphdr` — safer and avoids alignment/platform struct-padding issues, at negligible cost.
- **O(1) amortized flow/behavioral updates** via `unordered_map`, so throughput doesn't degrade as the number of tracked flows grows.
- **Sliding time windows** (not unbounded counters) for SYN-flood/port-scan detection, so detection is based on *rate*, not lifetime totals.
- **Background pruning thread** keeps memory bounded without slowing the packet-processing hot path.
- Compiled with `-O3` in Release mode.

## Build

Requires `libpcap` development headers (Linux: `sudo apt install libpcap-dev`; macOS: bundled with Xcode CLT).

```bash
cd CAIDS
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
```

This produces `./caids_nids`.

## Run

Live capture requires raw-socket privileges:

```bash
sudo ./caids_nids -i eth0 -f "tcp or udp or icmp"
```

Analyze a saved capture instead (no root needed):

```bash
./caids_nids -r sample.pcap
```

List available interfaces:

```bash
./caids_nids -l
```

## Detections included in this first module

- Malformed / truncated IPv4, TCP, UDP headers
- NULL scan (no TCP flags set)
- XMAS scan (FIN+PSH+URG)
- FIN scan (lone FIN, no ACK/SYN/RST)
- Invalid TCP flag combinations (SYN+FIN, SYN+RST)
- Suspiciously low TTL
- Port scan (many distinct destination ports from one source within a time window)
- SYN flood (high rate of unanswered SYNs from one source within a time window)

## Extending this module

This is intentionally the *detection engine* only, ready for the next
CAIDS stages to build on:

- Swap/extend the fixed thresholds in `FlowAnalyzer` for adaptive or
  statistical baselining (e.g. EWMA per-source packet rate) for higher
  accuracy against slow/low-and-slow scans.
- Feed `Alert` objects into a logging/alerting sink (file, syslog, SIEM,
  message queue) instead of `std::cout` — `main.cpp`'s `printAlert` is
  the single place to change.
- Add IPv6 and additional protocols to `PacketAnalyzer::parse`.
- A later CAIDS stage (e.g. "Signature/ML Analysis") can subscribe to
  the same `PacketInfo`/`Alert` types for deeper inspection.

## Legal / ethical note

Only run this against networks and traffic you own or are explicitly
authorized to monitor. Live packet capture typically requires elevated
privileges (root / `CAP_NET_RAW`) — use responsibly.
