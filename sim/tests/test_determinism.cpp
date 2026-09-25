// Determinism is the property the entire teaching and debugging workflow rests
// on. If a seeded run is not reproducible, then "it failed once on my machine" is
// unanswerable, and every lab exercise becomes a guessing game.

#include <gtest/gtest.h>

#include "airframe/state_machine.hpp"

using namespace airframe;

namespace {

SimConfig seeded(std::uint64_t seed, Fault f = Fault::None) {
    SimConfig c;
    c.security = Security::Wpa3Sae;
    c.band     = Band::Band5GHz;
    c.channel  = 36;
    c.width    = 80;
    c.phy      = Phy::Dot11ax;
    c.seed     = seed;
    c.fault.fault = f;
    return c;
}

std::string run_and_summarise(std::uint64_t seed, Fault f = Fault::None) {
    StateMachine sm(seeded(seed, f));
    sm.connect();
    if (sm.state() == State::Connected) sm.run_connected(500);
    return sm.session_summary_json();
}

}  // namespace

TEST(Determinism, SameSeedGivesIdenticalSummary) {
    EXPECT_EQ(run_and_summarise(42), run_and_summarise(42));
}

TEST(Determinism, SameSeedGivesIdenticalLogsLineForLine) {
    StateMachine a(seeded(7)), b(seeded(7));
    a.connect();
    b.connect();

    const auto& la = a.log_records();
    const auto& lb = b.log_records();
    ASSERT_EQ(la.size(), lb.size());
    for (std::size_t i = 0; i < la.size(); ++i) {
        EXPECT_EQ(la[i].message, lb[i].message)      << "log line " << i << " diverged";
        EXPECT_EQ(la[i].monotonic_ms, lb[i].monotonic_ms) << "timing at line " << i << " diverged";
        EXPECT_EQ(la[i].component, lb[i].component);
    }
}

TEST(Determinism, DifferentSeedsGiveDifferentDetails) {
    // Without this, "deterministic" could be satisfied by ignoring the seed
    // entirely -- which would silently destroy the variety the test matrix needs.
    EXPECT_NE(run_and_summarise(1), run_and_summarise(2));
}

TEST(Determinism, MacAddressesAreStableAcrossRunsWithTheSameSeed) {
    StateMachine a(seeded(99)), b(seeded(99));
    EXPECT_EQ(a.bssid_string(), b.bssid_string());
}

TEST(Determinism, GeneratedMacsAreLocallyAdministeredUnicast) {
    // Synthetic captures must not contain MACs that could be mistaken for real
    // vendor hardware. Bit 1 of the first octet set = locally administered;
    // bit 0 clear = unicast.
    StateMachine sm(seeded(5));
    const std::string bssid = sm.bssid_string();
    std::uint8_t mac[6];
    ASSERT_TRUE(string_to_mac(bssid, mac));
    EXPECT_EQ(mac[0] & 0x02, 0x02) << bssid << " must be locally administered";
    EXPECT_EQ(mac[0] & 0x01, 0x00) << bssid << " must be unicast";
}

TEST(Determinism, VirtualTimeAdvancesWithoutRealSleeping) {
    const auto wall_start = std::chrono::steady_clock::now();

    StateMachine sm(seeded(3));
    ASSERT_TRUE(sm.connect().ok);
    sm.run_connected(30000);          // thirty virtual seconds

    const auto wall_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - wall_start).count();

    EXPECT_GE(sm.now_ms(), 30000u) << "virtual time must have advanced";
    // The whole point: 30 virtual seconds cost almost no real time. A generous
    // bound keeps this from failing on a heavily loaded CI machine.
    EXPECT_LT(wall_elapsed, 2000) << "virtual time must not sleep for real";
}

TEST(Determinism, TimestampsAreTimezoneIndependent) {
    // Anchored to a fixed epoch rather than the host clock, so output does not
    // change with TZ or with the date. Using localtime() here would produce a
    // diff that only appears when someone runs the suite in another timezone.
    StateMachine sm(seeded(11));
    ASSERT_FALSE(sm.log_records().empty());
    EXPECT_EQ(sm.log_records()[0].timestamp.substr(0, 10), "2025-01-01");
    EXPECT_EQ(sm.log_records()[0].timestamp.back(), 'Z');
}

TEST(Determinism, FaultRunsAreAlsoReproducible) {
    for (const Fault f : {Fault::AuthTimeout, Fault::FourWayM3Timeout, Fault::DhcpNak,
                          Fault::PmkMismatch, Fault::AssocReject}) {
        EXPECT_EQ(run_and_summarise(21, f), run_and_summarise(21, f))
            << "fault " << to_string(f) << " is not reproducible";
    }
}

TEST(Determinism, ResetRestoresAReusableMachine) {
    StateMachine sm(seeded(8));
    ASSERT_TRUE(sm.connect().ok);
    sm.disconnect();
    sm.reset();
    EXPECT_EQ(sm.state(), State::Idle);
    EXPECT_EQ(sm.stats().tx_frames, 0u) << "reset must clear traffic counters";
    // A second connection on the same machine must still work -- the Python
    // backend reuses one process across many tests.
    EXPECT_TRUE(sm.connect().ok);
}
