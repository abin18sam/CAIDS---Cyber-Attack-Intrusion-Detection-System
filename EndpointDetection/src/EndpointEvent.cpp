#include "EndpointEvent.h"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace caids {
namespace endpoint {

std::string jsonEscape(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        switch (c) {
            case '"':  ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b";  break;
            case '\f': ss << "\\f";  break;
            case '\n': ss << "\\n";  break;
            case '\r': ss << "\\r";  break;
            case '\t': ss << "\\t";  break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

std::string getCurrentIsoTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm bt{};
#if defined(_WIN32)
    gmtime_s(&bt, &in_time_t);
#else
    gmtime_r(&in_time_t, &bt);
#endif

    std::ostringstream ss;
    ss << std::put_time(&bt, "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return ss.str();
}

std::string EndpointEvent::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"timestamp\":\"" << jsonEscape(timestamp.empty() ? getCurrentIsoTimestamp() : timestamp) << "\","
       << "\"host_id\":\"" << jsonEscape(host_id) << "\","
       << "\"event_type\":\"" << jsonEscape(event_type) << "\","
       << "\"process_name\":\"" << jsonEscape(process_name) << "\","
       << "\"pid\":" << pid << ","
       << "\"parent_pid\":" << parent_pid << ","
       << "\"user\":\"" << jsonEscape(user) << "\","
       << "\"exe_path\":\"" << jsonEscape(exe_path) << "\","
       << "\"command_line\":\"" << jsonEscape(command_line) << "\","
       << "\"severity\":\"" << jsonEscape(severity) << "\","
       << "\"reason\":\"" << jsonEscape(reason) << "\""
       << "}";
    return ss.str();
}

} // namespace endpoint
} // namespace caids
