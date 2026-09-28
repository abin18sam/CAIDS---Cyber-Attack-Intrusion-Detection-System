#pragma once

#include <string>
#include <cstdint>

namespace caids {
namespace endpoint {

struct EndpointEvent {
    std::string timestamp;        // ISO-8601 UTC string (e.g. 2026-09-28T10:20:31Z)
    std::string host_id;          // Unique host identifier
    std::string event_type;       // PROCESS_START, PROCESS_STOP, SUSPICIOUS_PROCESS, KEYLOGGER_INDICATOR
    std::string process_name;     // Name of executable
    uint32_t pid = 0;             // Process ID
    uint32_t parent_pid = 0;      // Parent Process ID
    std::string user;             // Process execution user
    std::string exe_path;         // Full path to binary
    std::string command_line;     // Command line arguments
    std::string severity = "INFO";// INFO, LOW, MEDIUM, HIGH, CRITICAL
    std::string reason;           // Rationale for alert/event

    std::string toJson() const;
};

std::string getCurrentIsoTimestamp();
std::string jsonEscape(const std::string& input);

} // namespace endpoint
} // namespace caids
