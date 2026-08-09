#pragma once
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <pcap.h>

// ============================================================================
// CAIDS Data Collection Service - PacketCapture
// libpcap wrapper. Same responsibility as in the NIDS skeleton: acquire raw
// frames efficiently. Used here in a retry/reconnect loop (see main.cpp) so
// the service survives interface flaps, cable pulls, NIC resets, etc.
// ============================================================================

namespace caids {

using RawPacketCallback = std::function<void(const struct pcap_pkthdr*, const unsigned char*)>;

class PacketCapture {
public:
    PacketCapture() = default;
    ~PacketCapture();

    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    bool openLive(const std::string& device, int snaplen, bool promiscuous, int timeout_ms);
    bool setFilter(const std::string& filter_expr);

    // Blocking. Returns false on hard error (caller should reconnect).
    bool startCapture(const RawPacketCallback& callback);
    void stopCapture();

    struct Stats {
        uint64_t packets_received = 0;
        uint64_t packets_dropped_kernel = 0;
        uint64_t packets_dropped_interface = 0;
    };
    Stats getStats() const;

    pcap_t* rawHandle() const { return handle_; }
    std::string lastError() const { return last_error_; }
    static std::vector<std::string> listDevices();

private:
    pcap_t* handle_ = nullptr;
    bpf_program bpf_filter_{};
    bool filter_compiled_ = false;
    std::string last_error_;

    static void pcapDispatchTrampoline(unsigned char* user,
                                        const struct pcap_pkthdr* header,
                                        const unsigned char* packet);
};

} // namespace caids
