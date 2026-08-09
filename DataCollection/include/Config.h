#pragma once
#include <string>
#include <unordered_map>

// ============================================================================
// CAIDS Data Collection Service - Config
// Minimal dependency-free key=value config file loader.
// ============================================================================

namespace caids {

struct CollectorConfig {
    std::string interface = "";              // e.g. "eth0" (empty = must be set)
    std::string bpf_filter = "ip";            // capture filter
    int snaplen = 65535;
    bool promiscuous = true;
    int read_timeout_ms = 1000;

    std::string output_dir = "/var/lib/caids/captures";
    std::string log_dir = "/var/log/caids";

    // Rotation: whichever limit is hit first triggers a new output file.
    int rotate_seconds = 3600;                // rotate every hour by default
    long rotate_max_bytes = 500L * 1024 * 1024; // 500 MB per file

    bool write_metadata_log = true;           // lightweight JSONL alongside raw pcap
    bool write_raw_pcap = true;                // full-fidelity .pcap files

    int stats_interval_seconds = 60;          // how often to log throughput stats
    int min_free_disk_percent = 10;           // warn/pause writing below this
    int reconnect_backoff_start_seconds = 2;  // initial retry delay on capture failure
    int reconnect_backoff_max_seconds = 60;   // cap on retry delay

    static CollectorConfig loadFromFile(const std::string& path, bool& ok);
};

} // namespace caids
