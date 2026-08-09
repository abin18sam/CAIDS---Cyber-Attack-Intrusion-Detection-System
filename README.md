# CAIDS — Cyber Attack Intrusion Detection System

> **A modular, production-grade Network Intrusion Detection System (NIDS) written in C++17.**

CAIDS is built around a clean pipeline architecture: raw packets are first **collected** from a live network interface (or saved `.pcap` file), then **analyzed** at both the individual-packet and the per-flow level to surface a wide range of network-layer attacks in real time.

---

## 🗂️ Project Structure

```
CAIDS_NetworkDetection/
├── NetworkDetection/          ← NIDS engine: packet & flow analysis + alerting
│   ├── CMakeLists.txt
│   ├── README.md
│   ├── include/
│   │   ├── Common.h           ← shared types (PacketInfo, Alert, FlowKey…)
│   │   ├── PacketCapture.h    ← libpcap wrapper interface
│   │   ├── PacketAnalyzer.h   ← single-packet signature analysis
│   │   └── FlowAnalyzer.h     ← per-flow & behavioural analysis
│   └── src/
│       ├── main.cpp           ← CLI, wiring, run summary
│       ├── PacketCapture.cpp
│       ├── PacketAnalyzer.cpp
│       └── FlowAnalyzer.cpp
│
└── DataCollection/            ← 24×7 always-on capture service
    ├── CMakeLists.txt
    ├── README.md
    ├── config/
    │   └── collector.conf     ← runtime configuration file
    ├── include/
    │   ├── Config.h           ← config struct & parser
    │   ├── DiskGuard.h        ← free-space monitor
    │   ├── Logger.h           ← levelled, timestamped logger
    │   ├── PacketCapture.h    ← libpcap wrapper
    │   ├── RotatingPcapWriter.h      ← time/size-rotating .pcap output
    │   └── RotatingMetadataWriter.h  ← time/size-rotating .jsonl metadata
    ├── scripts/
    │   └── install.sh         ← one-shot system installation script
    ├── src/
    │   ├── main.cpp           ← reconnect loop, signal handling
    │   ├── PacketCapture.cpp
    │   ├── Config.cpp
    │   ├── DiskGuard.cpp
    │   ├── RotatingPcapWriter.cpp
    │   └── RotatingMetadataWriter.cpp
    └── systemd/
        └── caids-data-collection.service  ← systemd unit for auto-start
```

---

## 🛠️ Full CAIDS Pipeline

```
                         ┌─────────────────────┐
                         │     CAIDS STARTS    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                      ┌─────────────────────────┐
                      │      DATA COLLECTION    │
                      └────────────┬────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
       ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
       │   NETWORK    │     │   ENDPOINT   │     │   USB / HID  │
       │    DATA      │     │    DATA      │     │    DATA      │
       └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
              │                    │                    │
              ▼                    ▼                    ▼
       Packet / Flow        Process / Event       Device Identity
         Features               Data                 Data
                                   │
                                   ▼
                         ┌─────────────────────┐
                         │ SOFTWARE KEYLOGGER  │
                         │     DETECTION       │
                         └──────────┬──────────┘
                                    │
                         ┌──────────┴──────────┐
                         │                     │
                         ▼                     ▼
                  Keyboard Hook/API      Suspicious Process
                    Indicators              Behavior
                         │                     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         Keylogger Risk Signal
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
        Network Detection     Endpoint Detection    USB/HID Detection
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ THREAT CORRELATION  │
                         │      ENGINE         │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    RISK SCORING     │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
                  LOW            MEDIUM       HIGH / CRITICAL
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │  ALERT GENERATION   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ REAL-TIME DASHBOARD │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ INCIDENT TIMELINE   │
                         │ & INVESTIGATION     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         RESPONSE / ADMIN ACTION
```

---

## 🔍 Module 1 — NetworkDetection (NIDS Engine)

### What it does

| Component | File(s) | Role |
|---|---|---|
| **Packet Capture** | `PacketCapture.*` | Wraps libpcap — opens a live NIC or an offline `.pcap`, applies a BPF filter, streams raw frames with **zero-copy** (no per-packet heap allocation in the hot path). |
| **Packet Analyzer** | `PacketAnalyzer.*` | Manually, bounds-checked parses Ethernet → IPv4 → TCP/UDP/ICMP into a `PacketInfo`. Runs **stateless, single-packet** signature checks. |
| **Flow Analyzer** | `FlowAnalyzer.*` | Maintains per-5-tuple flow stats and per-source sliding-window state (`unordered_map`, O(1) amortised) for **rate-based** attack detection. |
| **Orchestration** | `main.cpp` | CLI args, signal shutdown, run summary (packets, drops, alerts, active flows). |

### Detections

- ☑ Malformed / truncated IPv4, TCP, UDP headers
- ☑ NULL scan (no TCP flags)
- ☑ XMAS scan (FIN + PSH + URG)
- ☑ FIN scan (lone FIN, no ACK/SYN/RST)
- ☑ Invalid TCP flag combos (SYN+FIN, SYN+RST)
- ☑ Suspiciously low TTL
- ☑ Port scan — many distinct dst-ports from one source within a sliding window
- ☑ SYN flood — high rate of unanswered SYNs from one source within a sliding window

### Why it's efficient

| Design choice | Benefit |
|---|---|
| Zero-copy capture (libpcap buffer pointer) | No frame copy on the capture hot path |
| Manual bounds-checked header parsing | Safer than struct-cast; avoids platform alignment/padding issues |
| `unordered_map` O(1) amortised flow updates | Throughput stable as concurrent flows grow |
| Sliding time windows (not lifetime counters) | Catches *rate-based* slow scans that lifetime totals miss |
| Background pruning thread | Memory bounded without slowing the packet path |
| `-O3` Release build | Maximum compiler optimisation |

### Build

Requires `libpcap` development headers.

```bash
# Linux
sudo apt install libpcap-dev

# macOS — bundled with Xcode Command Line Tools

cd NetworkDetection
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
```

Produces: `./caids_nids`

### Run

```bash
# Live capture (requires root / CAP_NET_RAW)
sudo ./caids_nids -i eth0 -f "tcp or udp or icmp"

# Analyse a saved capture (no root needed)
./caids_nids -r sample.pcap

# List available interfaces
./caids_nids -l
```

---

## 📦 Module 2 — DataCollection (24×7 Capture Service)

```
  CAIDS PIPELINE
          │
          ▼
   DATA COLLECTION   ◄── this module
          │
     ┌────┴────┐
     ▼          ▼
 raw .pcap   metadata .jsonl    (fed into NetworkDetection & future modules)
```

### What makes it "24×7", not just "capture"

| Concern | How it's handled |
|---|---|
| **NIC resets / cable pulls** | Outer reconnect loop with exponential backoff — never exits on a transient failure. |
| **Disk filling over days/weeks** | Output rotates by **time and size**. `DiskGuard` pauses raw `.pcap` writes (metadata continues) when free space drops below `min_free_disk_percent`. |
| **Half-written files seen by readers** | `.pcap` files are written to a `.part` name and atomically `rename()`d to their final name on rotation — consumers only ever see complete files. |
| **Process death / reboot** | Ships as a `systemd` unit with `Restart=always`. |
| **Health visibility** | `Logger` writes timestamped, levelled logs to `/var/log/caids/collector.log`; stats (packet/byte counts, drops, current file) logged every `stats_interval_seconds`. |
| **Clean shutdown** | `SIGINT`/`SIGTERM` flush and close all writers gracefully. |
| **Least privilege** | systemd unit runs as unprivileged `caids` user with only `CAP_NET_RAW` / `CAP_NET_ADMIN` granted. |

### Output files

| File | Format | Use |
|---|---|---|
| `caids_<timestamp>.pcap` | Standard pcap | Full-fidelity raw packets; readable by Wireshark, tcpdump, or `pcap_open_offline`. |
| `caids_meta_<timestamp>.jsonl` | JSON Lines | One record per packet (`ts`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `length`, `ttl`) — lightweight, greppable. |

### Build

```bash
# Linux
sudo apt install libpcap-dev

cd DataCollection
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
```

Produces: `./caids_collector`

### Install as a systemd service

```bash
sudo ./scripts/install.sh
sudo nano /etc/caids/collector.conf   # set interface = <your NIC>
sudo systemctl enable --now caids-data-collection
sudo systemctl status caids-data-collection
tail -f /var/log/caids/collector.log
```

### Run without installing (foreground / testing)

```bash
sudo ./build/caids_collector -c config/collector.conf
```

### Config reference (`config/collector.conf`)

| Key | Meaning |
|---|---|
| `interface` | NIC to capture from (**required**) |
| `bpf_filter` | BPF expression, e.g. `ip`, `tcp or udp or icmp` |
| `snaplen`, `promiscuous`, `read_timeout_ms` | libpcap capture tuning |
| `output_dir`, `log_dir` | where captures and logs land |
| `rotate_seconds`, `rotate_max_bytes` | rotation thresholds |
| `write_raw_pcap`, `write_metadata_log` | toggle each output independently |
| `stats_interval_seconds` | health-stats logging cadence |
| `min_free_disk_percent` | pause raw pcap below this free-space % |
| `reconnect_backoff_start_seconds` / `_max_seconds` | reconnect retry pacing |

---

The two modules are **independently usable**:
- Run `caids_nids` directly on a live interface for interactive analysis.
- Or deploy `caids_collector` as a permanent capture daemon and feed its `.pcap` output into `caids_nids` offline.

---

## 📋 Requirements

| Dependency | Version | Notes |
|---|---|---|
| C++ compiler | C++17 | GCC ≥ 7, Clang ≥ 5 |
| CMake | ≥ 3.10 | |
| libpcap | any current | `libpcap-dev` on Debian/Ubuntu |
| pthreads | — | Pulled in automatically by CMake |
| systemd | — | Optional — only for DataCollection service |

---

## 🔐 Legal / Ethical Notice

> Only run CAIDS against networks and devices **you own or are explicitly authorized to monitor**.
> Live packet capture requires elevated privileges (`root` or `CAP_NET_RAW`).
> Unauthorized interception of network traffic is illegal in most jurisdictions.

---

## 🗺️ Roadmap / Extending CAIDS

- [ ] **Adaptive thresholds** — replace fixed SYN-flood / port-scan thresholds with EWMA-based per-source baselining for low-and-slow attack detection.
- [ ] **Alert sinks** — route `Alert` objects to file, syslog, Kafka, or a SIEM instead of stdout.
- [ ] **IPv6 & more protocols** — extend `PacketAnalyzer::parse` beyond IPv4/TCP/UDP/ICMP.
- [ ] **Signature / ML Analysis module** — a future CAIDS stage that consumes the same `PacketInfo` / `Alert` types for deeper inspection.
- [ ] **Web dashboard** — real-time alert and flow visualisation.
- [ ] **Unit & integration tests** — replay known-malicious `.pcap` files and assert correct alerts.

---

## 📄 License

This project is provided for educational and research purposes.
See individual module READMEs for detailed notes on responsible use.
