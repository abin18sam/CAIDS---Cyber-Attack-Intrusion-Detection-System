# CAIDS — Data Collection Service (24×7)

This is the **Data Collection** branch of CAIDS Network Detection, packaged
as a standalone, always-on service — not just a capture loop, but something
designed to run unattended indefinitely.

```
NETWORK DETECTION / NIDS
        │
        ▼
 DATA COLLECTION   ◄── this module
        │
   ┌────┴────┐
   ▼         ▼
raw .pcap   metadata .jsonl     (ready for Packet/Flow Analysis to consume)
```

## What makes this "24×7", not just "capture"

| Concern | How it's handled |
|---|---|
| **Interface drops / NIC resets / cable pulls** | `main.cpp` runs an outer reconnect loop: if `pcap_loop` ever exits without an explicit shutdown, it reopens the interface with exponential backoff (`reconnect_backoff_start_seconds` → `reconnect_backoff_max_seconds`) instead of exiting. |
| **Disk filling up over days/weeks** | Output rotates by time *and* size (`rotate_seconds`, `rotate_max_bytes`) into discrete files. A background thread checks free space (`DiskGuard`) and if it drops below `min_free_disk_percent`, raw `.pcap` writing is paused (metadata logging continues) rather than crashing or corrupting a file. |
| **Downstream consumers reading half-written files** | `.pcap` files are written to a `.part` temp name and atomically `rename()`d to their final name only once rotated/closed — a reader only ever sees complete files. |
| **Process death / reboot** | Ships as a `systemd` unit with `Restart=always`, meant to be enabled so it survives crashes and reboots. |
| **Visibility into health** | `Logger` writes timestamped, leveled logs to `/var/log/caids/collector.log` (and stdout under systemd/journald); a stats line (packet/byte counts, kernel/interface drop counts, current file) is logged every `stats_interval_seconds`. |
| **Clean shutdown** | `SIGINT`/`SIGTERM` (what `systemctl stop` sends) break the capture loop and flush/close writers properly. |
| **Least privilege** | The systemd unit runs as an unprivileged `caids` user with only `CAP_NET_RAW`/`CAP_NET_ADMIN` granted, not root. |

## Output

Two parallel outputs land in `output_dir` (default `/var/lib/caids/captures`):

- `caids_<timestamp>.pcap` — full-fidelity raw packets (standard pcap format,
  readable by Wireshark/tcpdump or by `pcap_open_offline` in the Packet
  Analysis / Flow Analysis modules).
- `caids_meta_<timestamp>.jsonl` — one JSON object per packet
  (`ts`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `length`, `ttl`)
  for lightweight, greppable visibility without needing to open a pcap file.

Both rotate independently on the same time/size thresholds.

## Build

Requires `libpcap-dev` (Linux) or the pcap headers bundled with Xcode CLT (macOS).

```bash
cd CAIDS_DataCollection
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
```

## Install as a 24/7 systemd service

```bash
sudo ./scripts/install.sh
sudo nano /etc/caids/collector.conf   # set interface = <your NIC>
sudo systemctl enable --now caids-data-collection
sudo systemctl status caids-data-collection
tail -f /var/log/caids/collector.log
```

Restarting the box, killing the process, or unplugging the NIC should all
result in the service automatically resuming collection.

## Run without installing (foreground, for testing)

```bash
sudo ./build/caids_collector -c config/collector.conf
```

## Config reference (`config/collector.conf`)

| Key | Meaning |
|---|---|
| `interface` | NIC to capture from (required) |
| `bpf_filter` | BPF expression, e.g. `ip`, `tcp or udp or icmp` |
| `snaplen`, `promiscuous`, `read_timeout_ms` | libpcap capture tuning |
| `output_dir`, `log_dir` | where captures and logs are written |
| `rotate_seconds`, `rotate_max_bytes` | rotation thresholds |
| `write_raw_pcap`, `write_metadata_log` | toggle each output independently |
| `stats_interval_seconds` | how often health stats are logged |
| `min_free_disk_percent` | pause raw pcap writes below this free-space % |
| `reconnect_backoff_start_seconds` / `_max_seconds` | reconnect retry pacing |

## Next steps in the CAIDS pipeline

This module only **collects**. Point the Packet Analysis and Flow Analysis
modules at the `.pcap` files landing in `output_dir` (e.g. process each file
as it's rotated in, via `pcap_open_offline`) to complete the Network
Detection pipeline described in the parent project.

## Legal / ethical note

Only run this against networks and traffic you own or are explicitly
authorized to monitor. Live packet capture requires elevated privileges.
