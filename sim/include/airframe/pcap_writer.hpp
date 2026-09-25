// Minimal libpcap-format writer (classic .pcap, not pcapng).
//
// Hand-rolled rather than linking libpcap, so the simulator has zero external
// dependencies and so the file format is visible rather than magic. The output is
// a genuine capture file: Wireshark, tshark and Scapy all open it normally.
//
// File layout:
//   [24-byte global header][packet header][packet data][packet header][data]...
//
// The link type is LINKTYPE_IEEE802_11_RADIOTAP (127), meaning every packet
// begins with a radiotap header (radio metadata: signal strength, channel, rate)
// followed by the 802.11 frame itself. That is exactly what a real monitor-mode
// capture from a Wi-Fi adapter looks like.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace airframe {

inline constexpr std::uint32_t kPcapMagic          = 0xA1B2C3D4;  // microsecond resolution
inline constexpr std::uint16_t kPcapVersionMajor   = 2;
inline constexpr std::uint16_t kPcapVersionMinor   = 4;
inline constexpr std::uint32_t kLinkTypeRadiotap   = 127;
inline constexpr std::uint32_t kDefaultSnapLen     = 65535;

// Radio metadata attached to each frame, rendered into a radiotap header.
struct RadioInfo {
    std::uint16_t freq_mhz   = 5180;
    std::uint8_t  rate_500kbps = 12;   // 6 Mbps, in 500 kbps units
    std::int8_t   rssi_dbm   = -45;
    bool          is_5ghz    = true;
    bool          bad_fcs    = false;
};

class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter();

    PcapWriter(const PcapWriter&)            = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    bool open(const std::string& path);
    void close();
    bool is_open() const noexcept { return fp_ != nullptr; }

    // Append one 802.11 frame, wrapped in a radiotap header.
    // `timestamp_ms` comes from the VirtualClock, so captures are deterministic.
    void write_frame(std::uint64_t timestamp_ms,
                     const std::vector<std::uint8_t>& dot11_frame,
                     const RadioInfo& radio);

    std::uint64_t frames_written() const noexcept { return count_; }

    // Exposed for unit tests: build the radiotap header in isolation.
    static std::vector<std::uint8_t> radiotap_header(const RadioInfo& radio);

private:
    std::FILE*    fp_    = nullptr;
    std::uint64_t count_ = 0;
};

}  // namespace airframe
