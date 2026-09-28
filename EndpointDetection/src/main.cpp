#include "EndpointEvent.h"
#include "EventCollector.h"
#include "ProcessMonitor.h"
#include "SuspiciousProcessDetector.h"
#include "KeyloggerDetector.h"

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

namespace {
std::atomic<bool> g_shutdown{false};

void handleSignal(int) {
    g_shutdown = true;
}
} // namespace

int main(int argc, char** argv) {
    using namespace caids::endpoint;

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    std::string log_file = "logs/endpoint_events.jsonl";
    std::string host_id = "HOST-001";
    int monitor_interval_ms = 1000;
    int keylogger_interval_ms = 3000;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) log_file = argv[++i];
        else if (arg == "-h" && i + 1 < argc) host_id = argv[++i];
    }

    std::cout << "======================================================================\n"
              << "   CAIDS — Endpoint Telemetry & Threat Detection Agent               \n"
              << "======================================================================\n";

    // 1. Initialize Event Collector
    auto& collector = EventCollector::instance();
    if (!collector.init(log_file, host_id)) {
        std::cerr << "[Main] Failed to initialize event collector!\n";
        return 1;
    }

    // 2. Initialize Detectors
    SuspiciousProcessDetector proc_detector;
    KeyloggerDetector keylog_detector(keylogger_interval_ms);

    keylog_detector.setAlertCallback([&collector](const EndpointEvent& alert) {
        collector.emit(alert);
    });

    // 3. Initialize Process Monitor
    ProcessMonitor proc_monitor(monitor_interval_ms);

    proc_monitor.setEventCallback([&](const ProcessInfo& p, const std::string& event_type) {
        // Build base endpoint event
        EndpointEvent ev;
        ev.host_id = host_id;
        ev.event_type = event_type;
        ev.process_name = p.process_name;
        ev.pid = p.pid;
        ev.parent_pid = p.parent_pid;
        ev.exe_path = p.exe_path;
        ev.command_line = p.command_line;
        ev.user = p.user;
        ev.severity = "INFO";

        // Emit telemetry event
        collector.emit(ev);

        // If new process started, analyze with detectors
        if (event_type == "PROCESS_START") {
            // Check for suspicious process patterns
            auto susAlert = proc_detector.inspect(p);
            if (susAlert) {
                susAlert->host_id = host_id;
                collector.emit(*susAlert);
            }

            // Check for keylogger indicators
            auto keyAlert = keylog_detector.inspectProcess(p);
            if (keyAlert) {
                keyAlert->host_id = host_id;
                collector.emit(*keyAlert);
            }
        }
    });

    // Start background monitors
    proc_monitor.start();
    keylog_detector.start();

    std::cout << "[Main] Endpoint Detection Agent is running.\n"
              << "  - Telemetry Output : " << log_file << "\n"
              << "  - Host Identifier  : " << host_id << "\n"
              << "Press Ctrl+C to terminate.\n\n";

    while (!g_shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "\n[Main] Clean shutdown initiated...\n";
    proc_monitor.stop();
    keylog_detector.stop();
    collector.close();
    std::cout << "[Main] Agent stopped.\n";

    return 0;
}
