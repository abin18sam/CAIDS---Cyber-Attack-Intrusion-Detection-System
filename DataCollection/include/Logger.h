#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iostream>
#include <ctime>

// ============================================================================
// CAIDS Data Collection Service - Logger
// Simple thread-safe leveled logger writing to stdout and a log file.
// Kept dependency-free so this module can run as a minimal 24/7 daemon.
// ============================================================================

namespace caids {

enum class LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3, CRITICAL = 4 };

class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void configure(const std::string& log_file_path, LogLevel min_level) {
        std::lock_guard<std::mutex> lock(mutex_);
        min_level_ = min_level;
        if (!log_file_path.empty()) {
            file_.open(log_file_path, std::ios::app);
        }
    }

    void log(LogLevel level, const std::string& component, const std::string& message) {
        if (level < min_level_) return;
        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        char timebuf[32];
        std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

        std::string line = std::string("[") + timebuf + "] [" + levelToString(level) +
                            "] [" + component + "] " + message;

        std::cout << line << std::endl;
        if (file_.is_open()) {
            file_ << line << std::endl;
            file_.flush();
        }
    }

    void debug(const std::string& c, const std::string& m) { log(LogLevel::DEBUG, c, m); }
    void info(const std::string& c, const std::string& m) { log(LogLevel::INFO, c, m); }
    void warn(const std::string& c, const std::string& m) { log(LogLevel::WARN, c, m); }
    void error(const std::string& c, const std::string& m) { log(LogLevel::ERROR, c, m); }
    void critical(const std::string& c, const std::string& m) { log(LogLevel::CRITICAL, c, m); }

private:
    Logger() = default;
    static const char* levelToString(LogLevel l) {
        switch (l) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARN: return "WARN";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::CRITICAL: return "CRITICAL";
        }
        return "?";
    }

    std::mutex mutex_;
    std::ofstream file_;
    LogLevel min_level_ = LogLevel::INFO;
};

} // namespace caids
