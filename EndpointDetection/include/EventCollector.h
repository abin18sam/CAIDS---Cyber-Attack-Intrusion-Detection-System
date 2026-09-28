#pragma once

#include "EndpointEvent.h"
#include <string>
#include <fstream>
#include <mutex>

namespace caids {
namespace endpoint {

class EventCollector {
public:
    static EventCollector& instance();

    bool init(const std::string& log_file_path, const std::string& host_id);
    void emit(EndpointEvent event);
    void close();

    const std::string& getHostId() const { return host_id_; }

private:
    EventCollector() = default;
    ~EventCollector();
    EventCollector(const EventCollector&) = delete;
    EventCollector& operator=(const EventCollector&) = delete;

    std::string log_file_path_;
    std::string host_id_ = "HOST-001";
    std::ofstream log_file_;
    std::mutex file_mutex_;
    bool initialized_ = false;
};

} // namespace endpoint
} // namespace caids
