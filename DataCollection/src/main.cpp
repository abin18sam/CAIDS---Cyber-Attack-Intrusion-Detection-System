#include "PacketCapture.h"
#include "RotatingPcapWriter.h"
#include "RotatingMetadataWriter.h"
#include "Config.h"
#include "Logger.h"
#include "DiskGuard.h"

#include <atomic>
#include <csignal>
#include <thread>
#include <chrono>
#include <iostream>
#include <mutex>
#include <algorithm>
#include <sys/stat.h>

// ============================================================================
// CAIDS Data Collection Service
//
// Runs the DATA COLLECTION branch of Network Detection / NIDS as a
// standalone, always-on process:
//   - reconnects with exponential backoff if the interface drops or
//     pcap_loop exits with an error, instead of exiting
//   - rotates both raw .pcap output and a lightweight JSONL metadata log
//     so files stay a manageable size and are ready for downstream
//     Packet Analysis / Flow Analysis modules to consume
//   - monitors free disk space and pauses raw-pcap writing (keeping only
//     the much smaller metadata log) if space runs low, rather than
//     crashing or corrupting a capture file
//   - logs periodic throughput/health stats
//   - shuts down cleanly on SIGINT/SIGTERM (e.g. from systemd)
// ============================================================================

namespace {

std::atomic<bool> g_shutdown{false};
caids::PacketCapture* g_active_capture = nullptr;
std::mutex g_capture_mutex;

void handleSignal(int) {
    g_shutdown = true;
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    if (g_active_capture) g_active_capture->stopCapture();
}

std::string configPathFromArgs(int argc, char** argv) {
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "-c") return argv[i + 1];
    }
    return "/etc/caids/collector.conf";
}

} // namespace

int main(int argc, char** argv) {
    using namespace caids;
    auto& logger = Logger::instance();

    std::string config_path = configPathFromArgs(argc, argv);
    bool cfg_ok = false;
    CollectorConfig cfg = CollectorConfig::loadFromFile(config_path, cfg_ok);

    if (!cfg_ok) {
        std::cerr << "[CAIDS-Collector] Could not read config file '" << config_path
                  << "'. Using built-in defaults; pass -c <path> for a config file.\n";
    }
    if (cfg.interface.empty()) {
        std::cerr << "[CAIDS-Collector] No 'interface' set in config (" << config_path
                  << "). Example: interface = eth0\n";
        return 1;
    }

    mkdir(cfg.log_dir.c_str(), 0755);
    logger.configure(cfg.log_dir + "/collector.log", LogLevel::INFO);
    logger.info("main", "CAIDS Data Collection service starting. interface=" + cfg.interface +
                         " filter=\"" + cfg.bpf_filter + "\" output_dir=" + cfg.output_dir);

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    RotatingMetadataWriter metadata_writer(cfg.output_dir, cfg.rotate_seconds, cfg.rotate_max_bytes);
    if (cfg.write_metadata_log) {
        if (!metadata_writer.open()) {
            logger.error("main", "Failed to open metadata writer; continuing without it.");
        }
    }

    uint64_t total_packets = 0, total_bytes = 0;
    int backoff_seconds = cfg.reconnect_backoff_start_seconds;

    // --- Outer resilience loop: keep the service alive 24/7 ---
    while (!g_shutdown) {
        PacketCapture capture;
        {
            std::lock_guard<std::mutex> lock(g_capture_mutex);
            g_active_capture = &capture;
        }

        if (!capture.openLive(cfg.interface, cfg.snaplen, cfg.promiscuous, cfg.read_timeout_ms)) {
            logger.error("main", "openLive failed: " + capture.lastError() +
                                   " - retrying in " + std::to_string(backoff_seconds) + "s");
            std::this_thread::sleep_for(std::chrono::seconds(backoff_seconds));
            backoff_seconds = std::min(backoff_seconds * 2, cfg.reconnect_backoff_max_seconds);
            continue;
        }
        if (!cfg.bpf_filter.empty() && !capture.setFilter(cfg.bpf_filter)) {
            logger.error("main", "setFilter failed: " + capture.lastError());
            std::this_thread::sleep_for(std::chrono::seconds(backoff_seconds));
            backoff_seconds = std::min(backoff_seconds * 2, cfg.reconnect_backoff_max_seconds);
            continue;
        }

        // Connection succeeded - reset backoff for the next time we need it.
        backoff_seconds = cfg.reconnect_backoff_start_seconds;
        logger.info("main", "Capture (re)started on " + cfg.interface);

        RotatingPcapWriter pcap_writer(cfg.output_dir, cfg.rotate_seconds, cfg.rotate_max_bytes);
        bool pcap_writer_ready = false;
        if (cfg.write_raw_pcap) {
            pcap_writer_ready = pcap_writer.open(capture.rawHandle());
            if (!pcap_writer_ready) {
                logger.error("main", "Failed to open raw pcap writer; metadata-only mode this run.");
            }
        }

        // Background thread: periodic stats + disk space monitoring.
        std::atomic<bool> stop_stats{false};
        std::thread stats_thread([&]() {
            while (!stop_stats && !g_shutdown) {
                std::this_thread::sleep_for(std::chrono::seconds(cfg.stats_interval_seconds));
                if (stop_stats || g_shutdown) break;

                auto s = capture.getStats();
                logger.info("stats",
                    "packets=" + std::to_string(total_packets) +
                    " bytes=" + std::to_string(total_bytes) +
                    " kernel_dropped=" + std::to_string(s.packets_dropped_kernel) +
                    " iface_dropped=" + std::to_string(s.packets_dropped_interface) +
                    " current_file=" + pcap_writer.currentFilePath());

                auto disk = checkDiskFreePercent(cfg.output_dir);
                if (disk.ok && disk.percent_free < cfg.min_free_disk_percent) {
                    logger.critical("diskguard",
                        "Free disk space low (" + std::to_string(disk.percent_free) +
                        "%) on " + cfg.output_dir + " - raw pcap writing will be skipped " +
                        "until space recovers. Metadata logging continues.");
                }
            }
        });

        bool disk_low = false;
        auto onRawPacket = [&](const struct pcap_pkthdr* header, const unsigned char* packet) {
            total_packets++;
            total_bytes += header->len;

            if (cfg.write_metadata_log) {
                QuickPacketSummary summary = quickParse(packet, header->caplen);
                metadata_writer.write(summary);
            }

            if (pcap_writer_ready && !disk_low) {
                pcap_writer.write(header, packet);
            }
        };

        bool ok = capture.startCapture(onRawPacket);

        stop_stats = true;
        if (stats_thread.joinable()) stats_thread.join();
        pcap_writer.close();

        {
            std::lock_guard<std::mutex> lock(g_capture_mutex);
            g_active_capture = nullptr;
        }

        if (g_shutdown) {
            logger.info("main", "Shutdown signal received - stopping cleanly.");
            break;
        }

        // pcap_loop exited on its own (interface down, error, etc.) without
        // a shutdown request: this is exactly the scenario the 24/7 design
        // has to survive. Log it and reconnect after a short backoff.
        logger.warn("main", std::string("Capture loop ended unexpectedly (") +
                             (ok ? "clean rc" : capture.lastError()) +
                             "). Reconnecting in " + std::to_string(backoff_seconds) + "s.");
        std::this_thread::sleep_for(std::chrono::seconds(backoff_seconds));
        backoff_seconds = std::min(backoff_seconds * 2, cfg.reconnect_backoff_max_seconds);
    }

    metadata_writer.close();
    logger.info("main", "CAIDS Data Collection service stopped. Total packets=" +
                          std::to_string(total_packets) + " bytes=" + std::to_string(total_bytes));
    return 0;
}
