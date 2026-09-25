// Unit tests for the transition table and the connection lifecycle.
//
// The table is tested as pure data, independent of any StateMachine instance.
// That is the payoff of keeping it a static pure function: you can exhaustively
// enumerate every (state, event) pair without constructing a simulator.

#include <gtest/gtest.h>

#include <set>

#include "airframe/state_machine.hpp"

using namespace airframe;

namespace {

SimConfig quiet_config(Security sec = Security::Wpa2Psk, Band band = Band::Band5GHz) {
    SimConfig c;
    c.security = sec;
    c.band     = band;
    c.channel  = (band == Band::Band2_4GHz) ? 6 : 36;
    c.width    = (band == Band::Band2_4GHz) ? 20 : 80;
    c.phy      = (band == Band::Band2_4GHz) ? Phy::Dot11n : Phy::Dot11ax;
    c.seed     = 1234;
    return c;   // no log_path, no pcap_path -> writes nothing to disk
}

}  // namespace

// ---------------------------------------------------------------- table

TEST(TransitionTable, LegalHappyPathTransitions) {
    EXPECT_TRUE(StateMachine::is_legal(State::Idle, Event::ScanStart));
    EXPECT_TRUE(StateMachine::is_legal(State::Scanning, Event::AuthStart));
    EXPECT_TRUE(StateMachine::is_legal(State::Authenticating, Event::AuthOk));
    EXPECT_TRUE(StateMachine::is_legal(State::Associating, Event::FourWayStart));
    EXPECT_TRUE(StateMachine::is_legal(State::FourWay, Event::DhcpStart));
    EXPECT_TRUE(StateMachine::is_legal(State::Dhcp, Event::LinkUp));
    EXPECT_TRUE(StateMachine::is_legal(State::Connected, Event::RoamStart));
    EXPECT_TRUE(StateMachine::is_legal(State::Roaming, Event::RoamOk));
    EXPECT_TRUE(StateMachine::is_legal(State::Disconnecting, Event::Disconnected));
}

TEST(TransitionTable, RejectsNonsensicalTransitions) {
    // These are the transitions that would indicate a genuine driver bug.
    EXPECT_FALSE(StateMachine::is_legal(State::Idle, Event::DhcpOk));
    EXPECT_FALSE(StateMachine::is_legal(State::Idle, Event::LinkUp));
    EXPECT_FALSE(StateMachine::is_legal(State::Scanning, Event::FourWayOk));
    EXPECT_FALSE(StateMachine::is_legal(State::Authenticating, Event::DhcpOk));
    EXPECT_FALSE(StateMachine::is_legal(State::Connected, Event::AuthOk));
    EXPECT_FALSE(StateMachine::is_legal(State::Failed, Event::LinkUp));
}

TEST(TransitionTable, ResetIsLegalFromEveryState) {
    // Reset is the escape hatch: whatever mess the DUT is in, the harness must be
    // able to put it back to a known state. A test rig that can get permanently
    // stuck is worse than no test rig.
    for (int i = 0; i <= static_cast<int>(State::Failed); ++i) {
        const auto s = static_cast<State>(i);
        EXPECT_TRUE(StateMachine::is_legal(s, Event::Reset))
            << "Reset must be legal from " << to_string(s);
        EXPECT_EQ(StateMachine::next_state(s, Event::Reset), State::Idle);
    }
}

TEST(TransitionTable, IllegalTransitionThrowsWithBothHalvesInMessage) {
    try {
        StateMachine::next_state(State::Idle, Event::DhcpOk);
        FAIL() << "expected IllegalTransition";
    } catch (const IllegalTransition& e) {
        EXPECT_EQ(e.from(), State::Idle);
        EXPECT_EQ(e.event(), Event::DhcpOk);
        const std::string msg = e.what();
        // The message must name both halves; "illegal transition" alone forces
        // the reader back into a debugger.
        EXPECT_NE(msg.find("IDLE"), std::string::npos);
        EXPECT_NE(msg.find("DHCP_OK"), std::string::npos);
    }
}

TEST(TransitionTable, EveryStateIsReachableFromIdle) {
    // Breadth-first search over the table. An unreachable state is dead code
    // pretending to be a feature, and this catches it automatically as the
    // machine grows.
    std::set<State> seen{State::Idle};
    bool grew = true;
    while (grew) {
        grew = false;
        for (const auto& [key, to] : StateMachine::table()) {
            if (seen.count(key.first) && !seen.count(to)) {
                seen.insert(to);
                grew = true;
            }
        }
    }
    for (int i = 0; i <= static_cast<int>(State::Failed); ++i) {
        const auto s = static_cast<State>(i);
        EXPECT_TRUE(seen.count(s)) << to_string(s) << " is unreachable from IDLE";
    }
}

TEST(TransitionTable, NoStateIsATrapExceptByDesign) {
    // Every state must have at least one outgoing transition. Reset guarantees
    // this, but the assertion documents the invariant explicitly.
    for (int i = 0; i <= static_cast<int>(State::Failed); ++i) {
        const auto s = static_cast<State>(i);
        int outgoing = 0;
        for (const auto& [key, to] : StateMachine::table()) {
            (void)to;
            if (key.first == s) ++outgoing;
        }
        EXPECT_GT(outgoing, 0) << to_string(s) << " has no outgoing transitions";
    }
}

// ---------------------------------------------------------------- lifecycle

TEST(Lifecycle, CleanConnectReachesConnected) {
    StateMachine sm(quiet_config());
    const ConnectResult r = sm.connect();

    EXPECT_TRUE(r.ok) << r.message;
    EXPECT_EQ(r.final_state, State::Connected);
    EXPECT_EQ(sm.state(), State::Connected);
    EXPECT_EQ(r.fault, Fault::None);
    EXPECT_EQ(r.status, StatusCode::Success);
    EXPECT_FALSE(r.ip_address.empty()) << "a connected station must have an address";
}

TEST(Lifecycle, StageTimingsAreAllPopulatedAndSumSensibly) {
    StateMachine sm(quiet_config());
    const ConnectResult r = sm.connect();
    ASSERT_TRUE(r.ok);

    EXPECT_GT(r.timings.scan_ms, 0u);
    EXPECT_GT(r.timings.auth_ms, 0u);
    EXPECT_GT(r.timings.assoc_ms, 0u);
    EXPECT_GT(r.timings.fourway_ms, 0u);
    EXPECT_GT(r.timings.dhcp_ms, 0u);

    const std::uint64_t parts = r.timings.scan_ms + r.timings.auth_ms + r.timings.assoc_ms +
                                r.timings.fourway_ms + r.timings.dhcp_ms;
    // Stages are sequential, so the parts cannot exceed the whole. They may fall
    // slightly short, because a few transitions happen between stages.
    EXPECT_LE(parts, r.timings.total_ms);
    EXPECT_GT(parts, r.timings.total_ms * 9 / 10)
        << "stage timings should account for most of the total";
}

TEST(Lifecycle, OpenNetworkSkipsTheFourWayHandshake) {
    StateMachine sm(quiet_config(Security::Open, Band::Band2_4GHz));
    const ConnectResult r = sm.connect();

    ASSERT_TRUE(r.ok) << r.message;
    // There is no handshake to time, so the field must be exactly zero rather
    // than "small" -- an open network has no EAPOL exchange at all.
    EXPECT_EQ(r.timings.fourway_ms, 0u);
}

TEST(Lifecycle, SecuredNetworkPerformsTheFourWayHandshake) {
    StateMachine sm(quiet_config(Security::Wpa3Sae));
    const ConnectResult r = sm.connect();
    ASSERT_TRUE(r.ok) << r.message;
    EXPECT_GT(r.timings.fourway_ms, 0u);
}

TEST(Lifecycle, DisconnectReturnsToIdle) {
    StateMachine sm(quiet_config());
    ASSERT_TRUE(sm.connect().ok);
    sm.disconnect();
    EXPECT_EQ(sm.state(), State::Idle);
}

TEST(Lifecycle, RoamFromConnectedChangesBssid) {
    StateMachine sm(quiet_config());
    ASSERT_TRUE(sm.connect().ok);
    const std::string before = sm.bssid_string();

    const ConnectResult r = sm.roam();
    EXPECT_TRUE(r.ok) << r.message;
    EXPECT_EQ(sm.state(), State::Connected);
    EXPECT_NE(sm.bssid_string(), before) << "a roam must land on a different BSS";
}

TEST(Lifecycle, RoamIsRefusedWhenNotConnected) {
    StateMachine sm(quiet_config());
    const ConnectResult r = sm.roam();   // still IDLE
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.message.find("CONNECTED"), std::string::npos);
}

TEST(Lifecycle, ScanFindsMultipleBssesInTheSameEss) {
    StateMachine sm(quiet_config());
    const auto found = sm.scan();
    ASSERT_GE(found.size(), 2u) << "roaming tests need at least two BSSes";
    EXPECT_EQ(found[0].ssid, found[1].ssid) << "same ESS means the same SSID";
    EXPECT_NE(found[0].bssid, found[1].bssid) << "different BSS means a different BSSID";
    EXPECT_EQ(sm.state(), State::Idle) << "a standalone scan should end back at IDLE";
}

TEST(Lifecycle, RunConnectedAccumulatesTrafficStatistics) {
    StateMachine sm(quiet_config());
    ASSERT_TRUE(sm.connect().ok);
    const auto before = sm.stats();

    EXPECT_TRUE(sm.run_connected(1000));
    const auto after = sm.stats();
    EXPECT_GT(after.tx_frames, before.tx_frames);
    EXPECT_GE(after.retry_rate, 0.0);
    EXPECT_LE(after.retry_rate, 1.0);
}

// ---------------------------------------------------------------- interop rules

TEST(InteropRules, SixGigahertzForbidsOpenAndWpa2) {
    // Not an arbitrary restriction: Wi-Fi 6E mandates WPA3 on 6 GHz. Encoding it
    // in the DUT means the interop matrix generates only valid combinations, and
    // the invalid ones fail for the *correct* reason.
    EXPECT_FALSE(security_supported_on_band(Security::Open, Band::Band6GHz));
    EXPECT_FALSE(security_supported_on_band(Security::Wpa2Psk, Band::Band6GHz));
    EXPECT_TRUE(security_supported_on_band(Security::Wpa3Sae, Band::Band6GHz));
    EXPECT_TRUE(security_supported_on_band(Security::Open, Band::Band2_4GHz));
}

TEST(InteropRules, PhyGenerationsAreBandConstrained) {
    EXPECT_FALSE(phy_supported_on_band(Phy::Dot11n, Band::Band6GHz));   // HT has no 6 GHz
    EXPECT_FALSE(phy_supported_on_band(Phy::Dot11ac, Band::Band2_4GHz)); // VHT is 5 GHz only
    EXPECT_FALSE(phy_supported_on_band(Phy::Dot11ac, Band::Band6GHz));
    EXPECT_TRUE(phy_supported_on_band(Phy::Dot11ax, Band::Band6GHz));
    EXPECT_TRUE(phy_supported_on_band(Phy::Dot11n, Band::Band2_4GHz));
}

TEST(InteropRules, IllegalCombinationIsRefusedBeforeAnyFramesAreSent) {
    SimConfig c = quiet_config(Security::Wpa2Psk, Band::Band6GHz);
    StateMachine sm(c);
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.final_state, State::Failed);
    EXPECT_EQ(r.status, StatusCode::InvalidAkmp);
    EXPECT_EQ(sm.frames_captured(), 0u)
        << "an impossible configuration must be refused without transmitting";
}

TEST(InteropRules, ChannelToFrequencyMapping) {
    EXPECT_EQ(channel_to_freq(Band::Band2_4GHz, 1), 2412);
    EXPECT_EQ(channel_to_freq(Band::Band2_4GHz, 6), 2437);
    EXPECT_EQ(channel_to_freq(Band::Band2_4GHz, 11), 2462);
    EXPECT_EQ(channel_to_freq(Band::Band2_4GHz, 14), 2484);   // the Japan special case
    EXPECT_EQ(channel_to_freq(Band::Band5GHz, 36), 5180);
    EXPECT_EQ(channel_to_freq(Band::Band5GHz, 149), 5745);
    EXPECT_EQ(channel_to_freq(Band::Band6GHz, 1), 5955);
    EXPECT_EQ(channel_to_freq(Band::Band2_4GHz, 99), 0) << "invalid channel -> 0";
}

TEST(InteropRules, LinkRateRespondsToWidthAndSignal) {
    // Wider channel -> higher rate, all else equal. This is the property that
    // makes width worth putting in the test matrix at all.
    SimConfig narrow = quiet_config();
    narrow.width = 20;
    SimConfig wide = quiet_config();
    wide.width = 160;

    StateMachine a(narrow), b(wide);
    ASSERT_TRUE(a.connect().ok);
    ASSERT_TRUE(b.connect().ok);
    EXPECT_LT(a.stats().tx_rate_mbps, b.stats().tx_rate_mbps);
}

TEST(InteropRules, PhyGenerationsCapChannelWidth) {
    // Found by the Python interop matrix: the DUT accepted 320MHz on 802.11ax and
    // 80MHz on 802.11n, both of which the spec forbids. See BUILD_JOURNAL.md #8.
    EXPECT_EQ(max_width_for_phy(Phy::Dot11n), 40);
    EXPECT_EQ(max_width_for_phy(Phy::Dot11ac), 160);
    EXPECT_EQ(max_width_for_phy(Phy::Dot11ax), 160);
    EXPECT_EQ(max_width_for_phy(Phy::Dot11be), 320);

    EXPECT_FALSE(phy_supports_width(Phy::Dot11n, 80));
    EXPECT_FALSE(phy_supports_width(Phy::Dot11ax, 320));
    EXPECT_TRUE(phy_supports_width(Phy::Dot11be, 320));
    EXPECT_TRUE(phy_supports_width(Phy::Dot11n, 40));
}

TEST(InteropRules, OverWideChannelIsRefusedBeforeTransmitting) {
    SimConfig c = quiet_config(Security::Wpa2Psk, Band::Band5GHz);
    c.phy   = Phy::Dot11n;
    c.width = 80;                      // 802.11n cannot do 80MHz
    StateMachine sm(c);
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, StatusCode::CapabilitiesMismatch);
    EXPECT_EQ(sm.frames_captured(), 0u);
    EXPECT_NE(r.message.find("at most 40MHz"), std::string::npos) << r.message;
}

TEST(Lifecycle, BackgroundScanWhileConnectedRetainsTheAssociation) {
    // Found by tests/performance/test_link.py: scanning while connected threw an
    // IllegalTransition. But a background (off-channel) scan is exactly how
    // roaming decisions are made, and the station never leaves the association.
    // See BUILD_JOURNAL.md #9.
    StateMachine sm(quiet_config());
    ASSERT_TRUE(sm.connect().ok);
    ASSERT_EQ(sm.state(), State::Connected);

    const auto found = sm.scan();
    EXPECT_FALSE(found.empty());
    EXPECT_EQ(sm.state(), State::Connected)
        << "a background scan must not drop the association";

    bool logged = false;
    for (const auto& rec : sm.log_records())
        if (rec.message.find("background scan") != std::string::npos) logged = true;
    EXPECT_TRUE(logged) << "a background scan should be distinguishable in the logs";
}

TEST(Lifecycle, ForegroundScanFromIdleStillTransitions) {
    // The counterpart: from IDLE, a scan genuinely is a state change.
    StateMachine sm(quiet_config());
    ASSERT_EQ(sm.state(), State::Idle);
    sm.scan();
    EXPECT_EQ(sm.state(), State::Idle) << "scan returns to IDLE when it started there";

    bool foreground = false;
    for (const auto& rec : sm.log_records())
        if (rec.message.find("scan request") != std::string::npos) foreground = true;
    EXPECT_TRUE(foreground);
}
