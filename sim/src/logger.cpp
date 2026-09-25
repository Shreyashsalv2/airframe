#include "airframe/logger.hpp"

#include <cstdio>
#include <iostream>

namespace airframe {

const char* to_string(LogLevel l) noexcept {
    switch (l) {
        case LogLevel::Debug:  return "DEBUG";
        case LogLevel::Info:   return "INFO";
        case LogLevel::Notice: return "NOTICE";
        case LogLevel::Warn:   return "WARN";
        case LogLevel::Error:  return "ERROR";
    }
    return "?????";
}

bool Logger::open(const std::string& path, bool also_stderr) {
    to_stderr_ = also_stderr;
    if (path.empty()) return true;
    file_.open(path, std::ios::out | std::ios::trunc);
    return file_.is_open();
}

void Logger::close() {
    if (file_.is_open()) file_.close();
}

std::string Logger::format(const LogRecord& r) {
    char buf[64];
    // Fixed-width columns so the file stays greppable and column-sliceable with
    // awk/cut — a log you can't process with shell tools is a log you won't process.
    std::snprintf(buf, sizeof(buf), "[%7llums] <%-6s> %-10s: ",
                  static_cast<unsigned long long>(r.monotonic_ms),
                  to_string(r.level), r.component.c_str());
    return r.timestamp + " " + buf + r.message;
}

void Logger::log(std::uint64_t monotonic_ms, const std::string& timestamp, LogLevel level,
                 const std::string& component, const std::string& message) {
    if (static_cast<int>(level) < static_cast<int>(min_level_)) return;

    LogRecord r{monotonic_ms, timestamp, level, component, message};
    const std::string line = format(r);
    records_.push_back(std::move(r));

    if (file_.is_open()) {
        file_ << line << '\n';
        // Flush on EVERY line, deliberately.
        //
        // std::ofstream buffers in userspace, so without this the file stays 0
        // bytes until the stream is destroyed -- meaning the Python test harness,
        // which reads the log while the simulator is still running, sees nothing.
        // A test rig whose logs only appear after the process exits cannot attach
        // evidence to a failing test, which is most of the point of having logs.
        //
        // The throughput cost is real but irrelevant here: a session writes tens
        // of lines, not millions. Durability beats throughput for diagnostics.
        file_.flush();
    }
    if (to_stderr_)      std::cerr << line << '\n';
}

}  // namespace airframe
