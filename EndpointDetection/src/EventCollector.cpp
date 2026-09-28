#include "EventCollector.h"
#include <iostream>
#include <filesystem>

namespace caids {
namespace endpoint {

EventCollector& EventCollector::instance() {
    static EventCollector inst;
    return inst;
}

EventCollector::~EventCollector() {
    close();
}

bool EventCollector::init(const std::string& log_file_path, const std::string& host_id) {
    std::lock_guard<std::mutex> lock(file_mutex_);
    log_file_path_ = log_file_path;
    host_id_ = host_id.empty() ? "HOST-001" : host_id;

    // Ensure parent directory exists
    try {
        std::filesystem::path path(log_file_path_);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
    } catch (const std::exception& e) {
        std::cerr << "[EventCollector] Error creating directories: " << e.what() << "\n";
    }

    log_file_.open(log_file_path_, std::ios::app);
    if (!log_file_.is_open()) {
        std::cerr << "[EventCollector] Failed to open log file: " << log_file_path_ << "\n";
        return false;
    }

    initialized_ = true;
    std::cout << "[EventCollector] Logging endpoint telemetry to: " << log_file_path_ << "\n";
    return true;
}

void EventCollector::emit(EndpointEvent event) {
    if (event.host_id.empty()) {
        event.host_id = host_id_;
    }
    if (event.timestamp.empty()) {
        event.timestamp = getCurrentIsoTimestamp();
    }

    std::string json_line = event.toJson();

    {
        std::lock_guard<std::mutex> lock(file_mutex_);
        if (log_file_.is_open()) {
            log_file_ << json_line << "\n";
            log_file_.flush();
        }
    }

    // Console output with color/highlight for high severity
    if (event.severity == "CRITICAL" || event.severity == "HIGH") {
        std::cout << "[ENDPOINT ALERT - " << event.severity << "] " 
                  << event.event_type << " | " << event.process_name << " (PID: " << event.pid << ") "
                  << ":: " << event.reason << "\n";
    } else {
        std::cout << "[ENDPOINT - " << event.event_type << "] " 
                  << event.process_name << " (PID: " << event.pid << ")\n";
    }
}

void EventCollector::close() {
    std::lock_guard<std::mutex> lock(file_mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
    }
    initialized_ = false;
}

} // namespace endpoint
} // namespace caids
