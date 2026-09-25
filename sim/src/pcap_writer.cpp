#include "airframe/pcap_writer.hpp"

#include <cstdio>
#include <cstring>

namespace airframe {
namespace {

// The pcap format is little-endian when the magic is written as 0xA1B2C3D4 and
// read back correctly. Writing explicit byte-order helpers rather than memcpy of
// a struct avoids two classic bugs: compiler struct padding silently inserting
// bytes, and the file differing between architectures.
void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

// Radiotap "present" bitmap — which optional fields follow the 8-byte header.
constexpr std::uint32_t kPresentFlags        = 1u << 1;
constexpr std::uint32_t kPresentRate         = 1u << 2;
constexpr std::uint32_t kPresentChannel      = 1u << 3;
constexpr std::uint32_t kPresentDbmAntSignal = 1u << 5;

constexpr std::uint8_t  kFlagBadFcs          = 0x40;

constexpr std::uint16_t kChanFlagsOfdm       = 0x0040;
constexpr std::uint16_t kChanFlags2GHz       = 0x0080;
constexpr std::uint16_t kChanFlags5GHz       = 0x0100;

}  // namespace

std::vector<std::uint8_t> PcapWriter::radiotap_header(const RadioInfo& radio) {
    std::vector<std::uint8_t> rt;
    rt.push_back(0);   // version — always 0
    rt.push_back(0);   // pad
    put_u16(rt, 0);    // length placeholder, patched below
    put_u32(rt, kPresentFlags | kPresentRate | kPresentChannel | kPresentDbmAntSignal);

    // Fields appear in ascending bit order, each aligned to its own natural size.
    // Getting this alignment wrong is THE classic radiotap bug: the file still
    // opens, but every field after the mistake is read from the wrong offset, so
    // signal strengths come out as nonsense and nobody suspects the writer.
    rt.push_back(radio.bad_fcs ? kFlagBadFcs : 0x00);    // offset 8,  FLAGS   (u8)
    rt.push_back(radio.rate_500kbps);                    // offset 9,  RATE    (u8)
    // CHANNEL is u16-aligned and offset 10 is already even — no pad needed.
    put_u16(rt, radio.freq_mhz);                         // offset 10, freq    (u16)
    put_u16(rt, static_cast<std::uint16_t>(              // offset 12, flags   (u16)
                    kChanFlagsOfdm |
                    (radio.is_5ghz ? kChanFlags5GHz : kChanFlags2GHz)));
    rt.push_back(static_cast<std::uint8_t>(radio.rssi_dbm));  // offset 14, dBm (s8)
    rt.push_back(0);                                     // offset 15, pad to even length

    const std::uint16_t len = static_cast<std::uint16_t>(rt.size());
    rt[2] = static_cast<std::uint8_t>(len & 0xFF);
    rt[3] = static_cast<std::uint8_t>((len >> 8) & 0xFF);
    return rt;
}

PcapWriter::~PcapWriter() { close(); }

bool PcapWriter::open(const std::string& path) {
    close();
    fp_ = std::fopen(path.c_str(), "wb");
    if (!fp_) return false;

    std::vector<std::uint8_t> hdr;
    put_u32(hdr, kPcapMagic);
    put_u16(hdr, kPcapVersionMajor);
    put_u16(hdr, kPcapVersionMinor);
    put_u32(hdr, 0);                  // thiszone — UTC
    put_u32(hdr, 0);                  // sigfigs  — unused in practice
    put_u32(hdr, kDefaultSnapLen);
    put_u32(hdr, kLinkTypeRadiotap);
    std::fwrite(hdr.data(), 1, hdr.size(), fp_);
    count_ = 0;
    return true;
}

void PcapWriter::close() {
    if (fp_) {
        std::fclose(fp_);
        fp_ = nullptr;
    }
}

void PcapWriter::write_frame(std::uint64_t timestamp_ms,
                             const std::vector<std::uint8_t>& dot11_frame,
                             const RadioInfo& radio) {
    if (!fp_) return;

    const std::vector<std::uint8_t> rt = radiotap_header(radio);
    const std::uint32_t total = static_cast<std::uint32_t>(rt.size() + dot11_frame.size());

    // Same fixed epoch as VirtualClock, so pcap timestamps and log timestamps
    // line up exactly — which is what makes timeline correlation possible later.
    const std::uint32_t sec  = static_cast<std::uint32_t>(1735689600ULL + timestamp_ms / 1000);
    const std::uint32_t usec = static_cast<std::uint32_t>((timestamp_ms % 1000) * 1000);

    std::vector<std::uint8_t> ph;
    put_u32(ph, sec);
    put_u32(ph, usec);
    put_u32(ph, total);   // captured length
    put_u32(ph, total);   // original length (no truncation — snaplen is 64K)

    std::fwrite(ph.data(), 1, ph.size(), fp_);
    std::fwrite(rt.data(), 1, rt.size(), fp_);
    if (!dot11_frame.empty())
        std::fwrite(dot11_frame.data(), 1, dot11_frame.size(), fp_);
    // Same reasoning as Logger::log -- the Python side analyses captures while
    // the simulator is still alive, so a buffered FILE* would hand it a
    // truncated file. Flushing per frame also means a crashed simulator leaves a
    // valid partial capture rather than an empty one, which is exactly when you
    // most want the capture.
    std::fflush(fp_);
    ++count_;
}

}  // namespace airframe
