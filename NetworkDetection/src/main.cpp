#include "PacketCapture.h"
#include "PacketAnalyzer.h"
#include "FlowAnalyzer.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>

// ============================================================================
// CAIDS - Cyber Attacks Intrusion Detection System
// Step 1: NETWORK DETECTION / NIDS
//
//        NETWORK DETECTION / NIDS
//                  |
//      +-----------+-----------+
//      v           v           v
// DATA COLLECTION  PACKET      FLOW
//                  ANALYSIS    ANALYSIS
//
// This binary wires the three branches together:
//   1. DATA COLLECTION  -> caids::PacketCapture   (src/PacketCapture.cpp)
//   2. PACKET ANALYSIS  -> caids::PacketAnalyzer  (src/PacketAnalyzer.cpp)
//   3. FLOW ANALYSIS    -> caids::FlowAnalyzer    (src/FlowAnalyzer.cpp)
// ============================================================================

namespace {
std::atomic<bool> g_stop{false};
caids::PacketCapture* g_capture_ptr = nullptr;

void handleSignal(int) {
    g_stop = true;
    if (g_capture_ptr) g_capture_ptr->stopCapture();
}

void printAlert(const caids::Alert& a) {
    auto t = std::chrono::system_clock::to_time_t(a.time);
    std::cout << "[ALERT] "
              << std::put_time(std::localtime(&t), "%H:%M:%S") << " "
              << "sev=" << a.severity << " "
              << "[" << a.source << "/" << a.category << "] "
              << a.src_ip << " -> " << a.dst_ip << " :: "
              << a.description << "\n";
}

void printUsage(const char* prog) {
    std::cout << "CAIDS - Network Detection (NIDS)\n"
              << "Usage:\n"
              << "  " << prog << " -i <interface> [-f \"<bpf filter>\"]\n"
              << "  " << prog << " -r <file.pcap>  [-f \"<bpf filter>\"]\n"
              << "  " << prog << " -l                 (list available interfaces)\n"
              << "\nExamples:\n"
              << "  sudo " << prog << " -i eth0 -f \"tcp or udp or icmp\"\n"
              << "  " << prog << " -r capture.pcap\n";
}
} // namespace

int main(int argc, char** argv) {
    std::string interface, pcap_file, filter = "tcp or udp or icmp";
    bool list_devices = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) interface = argv[++i];
        else if (arg == "-r" && i + 1 < argc) pcap_file = argv[++i];
        else if (arg == "-f" && i + 1 < argc) filter = argv[++i];
        else if (arg == "-l") list_devices = true;
        else if (arg == "-h" || arg == "--help") { printUsage(argv[0]); return 0; }
    }

    if (list_devices) {
        std::cout << "Available capture interfaces:\n";
        for (const auto& d : caids::PacketCapture::listDevices()) {
            std::cout << "  - " << d << "\n";
        }
        return 0;
    }

    if (interface.empty() && pcap_file.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    // ---- 1) DATA COLLECTION ----
    caids::PacketCapture capture;
    g_capture_ptr = &capture;
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    bool opened = interface.empty()
        ? capture.openOffline(pcap_file)
        : capture.openLive(interface);

    if (!opened) {
        std::cerr << "[DataCollection] Failed to open capture source: "
                  << capture.lastError() << "\n";
        return 1;
    }
    if (!filter.empty() && !capture.setFilter(filter)) {
        std::cerr << "[DataCollection] Failed to apply filter '" << filter
                  << "': " << capture.lastError() << "\n";
        return 1;
    }

    std::cout << "[CAIDS] Network Detection online. Source: "
              << (interface.empty() ? ("file:" + pcap_file) : ("iface:" + interface))
              << " | filter: \"" << filter << "\"\n";

    // ---- 2) PACKET ANALYSIS + 3) FLOW ANALYSIS ----
    caids::FlowAnalyzer flow_analyzer(/*syn_flood_threshold=*/100,
                                       /*port_scan_threshold=*/20,
                                       /*window=*/std::chrono::seconds(10));

    uint64_t total_packets = 0, parsed_packets = 0, alert_count = 0;

    // Background maintenance thread: evict idle flow/behavioral state so
    // memory use stays bounded on long-running captures.
    std::thread maintenance([&flow_analyzer]() {
        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            flow_analyzer.pruneIdle(std::chrono::seconds(300));
        }
    });

    auto onRawPacket = [&](const struct pcap_pkthdr* header, const unsigned char* packet) {
        total_packets++;

        // Branch: PACKET ANALYSIS
        auto parsed = caids::PacketAnalyzer::parse(header, packet);
        if (!parsed) return; // unsupported link type / non-IPv4, skip
        parsed_packets++;

        for (const auto& alert : caids::PacketAnalyzer::inspect(*parsed)) {
            printAlert(alert);
            alert_count++;
        }

        // Branch: FLOW ANALYSIS
        for (const auto& alert : flow_analyzer.update(*parsed)) {
            printAlert(alert);
            alert_count++;
        }
    };

    bool ok = capture.startCapture(onRawPacket);
    g_stop = true;
    if (maintenance.joinable()) maintenance.join();

    if (!ok) {
        std::cerr << "[DataCollection] Capture loop ended with error: "
                  << capture.lastError() << "\n";
    }

    auto stats = capture.getStats();
    std::cout << "\n--- CAIDS Network Detection Summary ---\n"
              << "Packets captured (libpcap):     " << stats.packets_received << "\n"
              << "Packets seen by callback:        " << total_packets << "\n"
              << "Packets parsed (IPv4):           " << parsed_packets << "\n"
              << "Dropped (kernel buffer):         " << stats.packets_dropped_kernel << "\n"
              << "Dropped (interface):             " << stats.packets_dropped_interface << "\n"
              << "Alerts raised:                   " << alert_count << "\n"
              << "Active flows at exit:             " << flow_analyzer.activeFlowCount() << "\n"
              << "Tracked source IPs at exit:       " << flow_analyzer.trackedSourceCount() << "\n";

    return ok ? 0 : 1;
}
