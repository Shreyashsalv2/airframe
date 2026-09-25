// Byte-level tests for the pcap writer.
//
// These matter more than they look: a wrong offset in the radiotap header still
// produces a file that opens cleanly, it just reports nonsense for every field
// after the mistake. That failure mode is invisible without explicit byte checks.

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <vector>

#include "airframe/pcap_writer.hpp"
#include "airframe/state_machine.hpp"

using namespace airframe;

namespace {

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f),
                                     std::istreambuf_iterator<char>());
}

std::uint32_t u32le(const std::vector<std::uint8_t>& b, std::size_t off) {
    return static_cast<std::uint32_t>(b[off]) |
           (static_cast<std::uint32_t>(b[off + 1]) << 8) |
           (static_cast<std::uint32_t>(b[off + 2]) << 16) |
           (static_cast<std::uint32_t>(b[off + 3]) << 24);
}

std::uint16_t u16le(const std::vector<std::uint8_t>& b, std::size_t off) {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(b[off]) |
                                      (static_cast<std::uint16_t>(b[off + 1]) << 8));
}

// Each test gets its own path so the suite can run in parallel under ctest.
std::string temp_path(const std::string& tag) {
    return "/tmp/airframe_test_" + tag + "_" + std::to_string(::getpid()) + ".pcap";
}

}  // namespace

TEST(PcapWriter, GlobalHeaderIsWellFormed) {
    const std::string path = temp_path("hdr");
    {
        PcapWriter w;
        ASSERT_TRUE(w.open(path));
    }
    const auto bytes = read_file(path);
    ASSERT_EQ(bytes.size(), 24u) << "an empty capture is exactly one 24-byte header";

    EXPECT_EQ(u32le(bytes, 0),  kPcapMagic);            // 0xA1B2C3D4
    EXPECT_EQ(u16le(bytes, 4),  kPcapVersionMajor);     // 2
    EXPECT_EQ(u16le(bytes, 6),  kPcapVersionMinor);     // 4
    EXPECT_EQ(u32le(bytes, 8),  0u);                    // thiszone
    EXPECT_EQ(u32le(bytes, 12), 0u);                    // sigfigs
    EXPECT_EQ(u32le(bytes, 16), kDefaultSnapLen);
    EXPECT_EQ(u32le(bytes, 20), kLinkTypeRadiotap);     // 127
    std::remove(path.c_str());
}

TEST(PcapWriter, RadiotapHeaderLayoutAndAlignment) {
    RadioInfo r;
    r.freq_mhz     = 5180;
    r.rate_500kbps = 12;
    r.rssi_dbm     = -45;
    r.is_5ghz      = true;

    const auto rt = PcapWriter::radiotap_header(r);

    EXPECT_EQ(rt[0], 0u) << "radiotap version is always 0";
    EXPECT_EQ(rt[1], 0u) << "pad byte";
    EXPECT_EQ(u16le(rt, 2), rt.size()) << "the length field must match the real length";
    EXPECT_EQ(u16le(rt, 2) % 2, 0u) << "keep the header even-length so the frame starts aligned";

    // present bitmap: FLAGS(1) | RATE(2) | CHANNEL(3) | DBM_ANTSIGNAL(5) = 0x2E
    EXPECT_EQ(u32le(rt, 4), 0x2Eu);

    // Fields follow in ascending bit order at fixed offsets.
    EXPECT_EQ(rt[8],  0u)  << "FLAGS: no bad-FCS bit";
    EXPECT_EQ(rt[9],  12u) << "RATE in 500kbps units";
    EXPECT_EQ(u16le(rt, 10), 5180u) << "CHANNEL frequency";
    EXPECT_EQ(static_cast<std::int8_t>(rt[14]), -45) << "signed dBm antenna signal";
}

TEST(PcapWriter, BadFcsFlagIsSet) {
    RadioInfo r;
    r.bad_fcs = true;
    const auto rt = PcapWriter::radiotap_header(r);
    EXPECT_EQ(rt[8] & 0x40, 0x40) << "bit 6 of FLAGS marks a bad FCS";
}

TEST(PcapWriter, TwoPointFourGhzSetsTheCorrectChannelFlag) {
    RadioInfo r;
    r.freq_mhz = 2437;
    r.is_5ghz  = false;
    const auto rt = PcapWriter::radiotap_header(r);
    const std::uint16_t chan_flags = u16le(rt, 12);
    EXPECT_EQ(chan_flags & 0x0080, 0x0080) << "2 GHz flag";
    EXPECT_EQ(chan_flags & 0x0100, 0x0000) << "5 GHz flag must be clear";
}

TEST(PcapWriter, PacketRecordLengthsMatchTheData) {
    const std::string path = temp_path("rec");
    const std::vector<std::uint8_t> frame(60, 0xAB);
    {
        PcapWriter w;
        ASSERT_TRUE(w.open(path));
        RadioInfo r;
        w.write_frame(1500, frame, r);
        EXPECT_EQ(w.frames_written(), 1u);
    }

    const auto bytes = read_file(path);
    const std::size_t rt_len = PcapWriter::radiotap_header(RadioInfo{}).size();

    // Packet record header sits at offset 24, immediately after the global header.
    const std::uint32_t ts_sec   = u32le(bytes, 24);
    const std::uint32_t ts_usec  = u32le(bytes, 28);
    const std::uint32_t incl_len = u32le(bytes, 32);
    const std::uint32_t orig_len = u32le(bytes, 36);

    EXPECT_EQ(incl_len, rt_len + frame.size());
    EXPECT_EQ(orig_len, incl_len) << "nothing is truncated at a 64K snaplen";
    EXPECT_EQ(ts_usec, 500000u)   << "1500ms -> .500s";
    EXPECT_EQ(ts_sec, 1735689600u + 1u) << "fixed epoch + 1 second";
    EXPECT_EQ(bytes.size(), 24u + 16u + incl_len);
    std::remove(path.c_str());
}

TEST(PcapWriter, TimestampsAreMonotonicAcrossAWholeSession) {
    const std::string path = temp_path("mono");
    SimConfig c;
    c.seed      = 77;
    c.pcap_path = path;
    {
        StateMachine sm(c);
        ASSERT_TRUE(sm.connect().ok);
        sm.run_connected(1000);
        sm.disconnect();
    }

    const auto bytes = read_file(path);
    ASSERT_GT(bytes.size(), 24u);

    std::uint64_t previous = 0;
    std::size_t   off      = 24;
    int           frames   = 0;
    while (off + 16 <= bytes.size()) {
        const std::uint64_t sec  = u32le(bytes, off);
        const std::uint64_t usec = u32le(bytes, off + 4);
        const std::uint32_t len  = u32le(bytes, off + 8);
        const std::uint64_t t    = sec * 1000000ull + usec;

        EXPECT_GE(t, previous) << "frame " << frames << " goes backwards in time";
        previous = t;
        off += 16 + len;
        ++frames;
    }
    EXPECT_EQ(off, bytes.size()) << "record lengths must tile the file exactly";
    EXPECT_GT(frames, 10);
    std::remove(path.c_str());
}

TEST(PcapWriter, NoPathMeansNoFileAndNoCrash) {
    // The unit tests run with pcap disabled; writing must degrade to a no-op
    // rather than throwing or writing to a stray path.
    SimConfig c;
    c.seed = 5;                 // pcap_path deliberately empty
    StateMachine sm(c);
    EXPECT_TRUE(sm.connect().ok);
    EXPECT_EQ(sm.frames_captured(), 0u);
}
