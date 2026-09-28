#include "SuspiciousProcessDetector.h"
#include <algorithm>

namespace caids {
namespace endpoint {

SuspiciousProcessDetector::SuspiciousProcessDetector() {
    // Default high-risk launch locations
    suspicious_paths_ = {
        "\\appdata\\local\\temp",
        "\\windows\\temp",
        "\\users\\public",
        "/tmp",
        "/var/tmp"
    };

    // System processes that should only run from System32
    protected_system_binaries_ = {
        "svchost.exe", "lsass.exe", "csrss.exe", 
        "services.exe", "smss.exe", "wininit.exe", "winlogon.exe"
    };

    // Suspicious parent processes (e.g. Office, PDF readers, browsers)
    suspicious_parents_ = {
        "winword.exe", "excel.exe", "powerpnt.exe",
        "acrord32.exe", "acrobat.exe", "outlook.exe",
        "chrome.exe", "firefox.exe", "msedge.exe"
    };

    // Dangerous child interpreters
    dangerous_children_ = {
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "cscript.exe", "wscript.exe", "mshta.exe",
        "certutil.exe", "vssadmin.exe", "bitsadmin.exe"
    };

    // Suspicious command line keywords
    suspicious_cli_keywords_ = {
        "-enc", "-encodedcommand", "downloadstring",
        "bypass", "invoke-expression", "iex",
        "vssadmin delete shadows", "certutil -urlcache",
        "net user /add", "wmic shadowcopy delete"
    };
}

std::string SuspiciousProcessDetector::toLower(const std::string& str) const {
    std::string out = str;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return out;
}

bool SuspiciousProcessDetector::containsIgnoreCase(const std::string& haystack, const std::string& needle) const {
    std::string h = toLower(haystack);
    std::string n = toLower(needle);
    return h.find(n) != std::string::npos;
}

void SuspiciousProcessDetector::addSuspiciousPath(const std::string& path_fragment) {
    suspicious_paths_.push_back(toLower(path_fragment));
}

void SuspiciousProcessDetector::addProtectedBinary(const std::string& binary_name) {
    protected_system_binaries_.push_back(toLower(binary_name));
}

void SuspiciousProcessDetector::addSuspiciousParent(const std::string& parent_name) {
    suspicious_parents_.push_back(toLower(parent_name));
}

void SuspiciousProcessDetector::addDangerousChild(const std::string& child_name) {
    dangerous_children_.push_back(toLower(child_name));
}

void SuspiciousProcessDetector::addSuspiciousCliKeyword(const std::string& keyword) {
    suspicious_cli_keywords_.push_back(toLower(keyword));
}

std::optional<EndpointEvent> SuspiciousProcessDetector::inspect(const ProcessInfo& proc, const std::string& parent_name) {
    std::string procNameLower = toLower(proc.process_name);
    std::string pathLower = toLower(proc.exe_path);
    std::string parentLower = toLower(parent_name);
    std::string cliLower = toLower(proc.command_line);

    EndpointEvent alert;
    alert.event_type = "SUSPICIOUS_PROCESS";
    alert.process_name = proc.process_name;
    alert.pid = proc.pid;
    alert.parent_pid = proc.parent_pid;
    alert.exe_path = proc.exe_path;
    alert.command_line = proc.command_line;
    alert.user = proc.user;

    // Check 1: Masquerading System Process
    for (const auto& sysBin : protected_system_binaries_) {
        if (procNameLower == sysBin) {
            bool inSystem32 = (pathLower.find("system32") != std::string::npos ||
                               pathLower.find("syswow64") != std::string::npos);
            if (!inSystem32 && !pathLower.empty() && pathLower != procNameLower) {
                alert.severity = "CRITICAL";
                alert.reason = "Protected system binary masquerading outside System32 directory: " + proc.exe_path;
                return alert;
            }
        }
    }

    // Check 2: Abnormal Parent-Child execution (e.g. Word/Browser spawning PowerShell/cmd)
    if (!parentLower.empty()) {
        bool isSuspiciousParent = std::any_of(suspicious_parents_.begin(), suspicious_parents_.end(),
            [&](const std::string& p) { return parentLower.find(p) != std::string::npos; });

        bool isDangerousChild = std::any_of(dangerous_children_.begin(), dangerous_children_.end(),
            [&](const std::string& c) { return procNameLower.find(c) != std::string::npos; });

        if (isSuspiciousParent && isDangerousChild) {
            alert.severity = "CRITICAL";
            alert.reason = "Suspicious process spawn: Application '" + parent_name + 
                           "' launched shell/script interpreter '" + proc.process_name + "'";
            return alert;
        }
    }

    // Check 3: Launch from untrusted/temporary paths
    for (const auto& badPath : suspicious_paths_) {
        if (pathLower.find(badPath) != std::string::npos) {
            alert.severity = "HIGH";
            alert.reason = "Executable launched from suspicious temporary or public directory: " + proc.exe_path;
            return alert;
        }
    }

    // Check 4: Suspicious command line arguments (e.g. encoded powershell, shadow copy deletion)
    if (!cliLower.empty()) {
        for (const auto& keyword : suspicious_cli_keywords_) {
            if (cliLower.find(keyword) != std::string::npos) {
                alert.severity = "HIGH";
                alert.reason = "Suspicious command-line pattern or obfuscation detected: keyword '" + keyword + "'";
                return alert;
            }
        }
    }

    return std::nullopt;
}

} // namespace endpoint
} // namespace caids
