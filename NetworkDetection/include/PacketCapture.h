#pragma once
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <pcap.h>

// ============================================================================
// CAIDS - Network Detection / NIDS
// Module: DATA COLLECTION
//
// Thin, efficient wrapper around libpcap responsible only for acquiring
// raw frames from a live interface or an offline .pcap file and handing
// them off (zero-copy, via pointer) to the Packet Analysis stage.
// ============================================================================

namespace caids {

using RawPacketCallback = std::function<void(const struct pcap_pkthdr*, const unsigned char*)>;

class PacketCapture {
public:
    PacketCapture() = default;
    ~PacketCapture();

    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Open a live network interface for capture.
    bool openLive(const std::string& device, int snaplen = 65535,
                  bool promiscuous = true, int timeout_ms = 1000);

    // Open a previously recorded .pcap file (useful for testing/replay).
    bool openOffline(const std::string& filename);

    // Apply a Berkeley Packet Filter expression, e.g. "tcp or udp or icmp"
    bool setFilter(const std::string& filter_expr);

    // Blocking capture loop. count == -1 -> run until stopCapture()/EOF.
    // Returns false if the underlying pcap_loop call failed.
    bool startCapture(const RawPacketCallback& callback, int count = -1);

    // Thread-safe request to stop an in-progress startCapture() loop.
    void stopCapture();

    // Basic per-session counters, useful for a status/efficiency report.
    struct Stats {
        uint64_t packets_received = 0;
        uint64_t packets_dropped_kernel = 0;
        uint64_t packets_dropped_interface = 0;
    };
    Stats getStats() const;

    std::string lastError() const { return last_error_; }
    static std::vector<std::string> listDevices();

private:
    pcap_t* handle_ = nullptr;
    bpf_program bpf_filter_{};
    bool filter_compiled_ = false;
    std::string last_error_;
    std::atomic<bool> stop_requested_{false};

    static void pcapDispatchTrampoline(unsigned char* user,
                                        const struct pcap_pkthdr* header,
                                        const unsigned char* packet);
};

} // namespace caids
