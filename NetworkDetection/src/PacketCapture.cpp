#include "PacketCapture.h"
#include <cstring>
#include <iostream>

namespace caids {

PacketCapture::~PacketCapture() {
    if (filter_compiled_) {
        pcap_freecode(&bpf_filter_);
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PacketCapture::openLive(const std::string& device, int snaplen,
                              bool promiscuous, int timeout_ms) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    handle_ = pcap_open_live(device.c_str(), snaplen, promiscuous ? 1 : 0,
                              timeout_ms, errbuf);
    if (!handle_) {
        last_error_ = errbuf;
        return false;
    }

    // Ensure we're actually looking at Ethernet frames; this NIDS's
    // packet analyzer assumes an Ethernet link-layer header.
    if (pcap_datalink(handle_) != DLT_EN10MB) {
        last_error_ = "Unsupported link-layer type on device '" + device +
                       "' (only Ethernet is supported)";
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }

    return true;
}

bool PacketCapture::openOffline(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle_) {
        last_error_ = errbuf;
        return false;
    }
    return true;
}

bool PacketCapture::setFilter(const std::string& filter_expr) {
    if (!handle_) {
        last_error_ = "setFilter() called before openLive()/openOffline()";
        return false;
    }
    if (filter_compiled_) {
        pcap_freecode(&bpf_filter_);
        filter_compiled_ = false;
    }
    if (pcap_compile(handle_, &bpf_filter_, filter_expr.c_str(), 1,
                      PCAP_NETMASK_UNKNOWN) == -1) {
        last_error_ = pcap_geterr(handle_);
        return false;
    }
    filter_compiled_ = true;
    if (pcap_setfilter(handle_, &bpf_filter_) == -1) {
        last_error_ = pcap_geterr(handle_);
        return false;
    }
    return true;
}

// pcap_loop needs a plain C function pointer; we smuggle the real
// std::function through the `user` parameter.
void PacketCapture::pcapDispatchTrampoline(unsigned char* user,
                                            const struct pcap_pkthdr* header,
                                            const unsigned char* packet) {
    auto* callback = reinterpret_cast<RawPacketCallback*>(user);
    (*callback)(header, packet);
}

bool PacketCapture::startCapture(const RawPacketCallback& callback, int count) {
    if (!handle_) {
        last_error_ = "startCapture() called before openLive()/openOffline()";
        return false;
    }
    stop_requested_ = false;

    // pcap_loop blocks; a background thread can call stopCapture() to
    // invoke pcap_breakloop() and unwind this cleanly.
    RawPacketCallback cb_copy = callback; // stable address for the trampoline
    int rc = pcap_loop(handle_, count, &PacketCapture::pcapDispatchTrampoline,
                        reinterpret_cast<unsigned char*>(&cb_copy));

    if (rc == -1) {
        last_error_ = pcap_geterr(handle_);
        return false;
    }
    // rc == -2 means pcap_breakloop() was called (intentional stop) - success.
    return true;
}

void PacketCapture::stopCapture() {
    stop_requested_ = true;
    if (handle_) {
        pcap_breakloop(handle_);
    }
}

PacketCapture::Stats PacketCapture::getStats() const {
    Stats s{};
    if (!handle_) return s;
    struct pcap_stat ps{};
    if (pcap_stats(handle_, &ps) == 0) {
        s.packets_received = ps.ps_recv;
        s.packets_dropped_kernel = ps.ps_drop;
        s.packets_dropped_interface = ps.ps_ifdrop;
    }
    return s;
}

std::vector<std::string> PacketCapture::listDevices() {
    std::vector<std::string> devices;
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[DataCollection] pcap_findalldevs failed: " << errbuf << "\n";
        return devices;
    }
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        devices.emplace_back(d->name ? d->name : "unknown");
    }
    pcap_freealldevs(alldevs);
    return devices;
}

} // namespace caids
