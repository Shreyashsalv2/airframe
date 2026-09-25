// Structured logging in the shape of a real wireless daemon.
//
// Deliberately formatted to look like Apple's `wifid` / wpa_supplicant output,
// because the point of the whole project is practising on logs that resemble the
// ones an engineer actually receives:
//
//   2025-01-01T00:00:01.240Z [   1240ms] <NOTICE > wifid      : assoc resp status=0 aid=3 bssid=02:1a:...
//   ^ wall-ish timestamp     ^ monotonic ^ level  ^ component ^ message with key=value pairs
//
// The monotonic column is the important one: it is the clock every layer
// correlates on (logs, pcap frames, KPI samples all share it), and unlike the
// wall-clock timestamp it never jumps.
//
// Messages are key=value because that makes template mining tractable later —
// a log line that interpolates values into free prose is far harder to cluster.
#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace airframe {

enum class LogLevel : std::uint8_t { Debug, Info, Notice, Warn, Error };

const char* to_string(LogLevel l) noexcept;

struct LogRecord {
    std::uint64_t monotonic_ms = 0;
    std::string   timestamp;
    LogLevel      level     = LogLevel::Info;
    std::string   component;   // wifid | supplicant | dhcp | driver | kernel
    std::string   message;
};

class Logger {
public:
    Logger() = default;

    // Writes to a file if `path` is non-empty, and optionally mirrors to stderr.
    bool open(const std::string& path, bool also_stderr = false);
    void close();

    void log(std::uint64_t monotonic_ms, const std::string& timestamp, LogLevel level,
             const std::string& component, const std::string& message);

    const std::vector<LogRecord>& records() const noexcept { return records_; }
    void clear() noexcept { records_.clear(); }

    // Format a single record the way it appears in the file. Exposed so tests can
    // assert on the exact wire format without touching the filesystem.
    static std::string format(const LogRecord& r);

    void set_min_level(LogLevel l) noexcept { min_level_ = l; }

private:
    std::ofstream          file_;
    bool                   to_stderr_ = false;
    LogLevel               min_level_ = LogLevel::Debug;
    std::vector<LogRecord> records_;
};

}  // namespace airframe
