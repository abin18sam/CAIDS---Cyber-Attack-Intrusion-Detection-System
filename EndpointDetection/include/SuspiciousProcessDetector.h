#pragma once

#include "EndpointEvent.h"
#include "ProcessMonitor.h"
#include <string>
#include <vector>
#include <optional>

namespace caids {
namespace endpoint {

class SuspiciousProcessDetector {
public:
    SuspiciousProcessDetector();

    // Configure custom rule patterns
    void addSuspiciousPath(const std::string& path_fragment);
    void addProtectedBinary(const std::string& binary_name);
    void addSuspiciousParent(const std::string& parent_name);
    void addDangerousChild(const std::string& child_name);
    void addSuspiciousCliKeyword(const std::string& keyword);

    // Evaluate process and return alert if suspicious
    std::optional<EndpointEvent> inspect(const ProcessInfo& proc, const std::string& parent_name = "");

private:
    std::string toLower(const std::string& str) const;
    bool containsIgnoreCase(const std::string& haystack, const std::string& needle) const;

    std::vector<std::string> suspicious_paths_;
    std::vector<std::string> protected_system_binaries_;
    std::vector<std::string> suspicious_parents_;
    std::vector<std::string> dangerous_children_;
    std::vector<std::string> suspicious_cli_keywords_;
};

} // namespace endpoint
} // namespace caids
