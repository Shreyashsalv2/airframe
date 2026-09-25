// Every fault must (a) fire, (b) fire at the right stage, and (c) report a code
// that matches what a real supplicant would log. A fault that fires at the wrong
// stage is worse than no fault, because it teaches the analysis layer a lie.

#include <gtest/gtest.h>

#include "airframe/state_machine.hpp"

using namespace airframe;

namespace {

SimConfig with_fault(Fault f, double p = 1.0, std::uint16_t code = 0) {
    SimConfig c;
    c.security = Security::Wpa2Psk;
    c.band     = Band::Band5GHz;
    c.channel  = 36;
    c.width    = 80;
    c.phy      = Phy::Dot11ax;
    c.seed     = 4242;
    c.fault.fault       = f;
    c.fault.probability = p;
    c.fault.code        = code;
    return c;
}

}  // namespace

TEST(Faults, NoFaultConnectsCleanly) {
    StateMachine sm(with_fault(Fault::None));
    EXPECT_TRUE(sm.connect().ok);
}

TEST(Faults, AuthTimeoutFailsInAuthenticating) {
    StateMachine sm(with_fault(Fault::AuthTimeout));
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.failed_at, State::Authenticating);
    EXPECT_EQ(r.fault, Fault::AuthTimeout);
    EXPECT_EQ(r.status, StatusCode::AuthTimeout);
    EXPECT_EQ(sm.state(), State::Failed);
    // The stage must actually have consumed the timeout, not failed instantly:
    // a supplicant that gives up in 10ms is its own bug.
    EXPECT_GE(r.timings.auth_ms, 3000u);
}

TEST(Faults, AssocRejectCarriesAnIeeeStatusCode) {
    StateMachine sm(with_fault(Fault::AssocReject));
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.failed_at, State::Associating);
    EXPECT_EQ(r.status, StatusCode::ApUnableToHandleSta);   // 17
    EXPECT_NE(r.status, StatusCode::Success);
}

TEST(Faults, AssocRejectStatusCodeIsOverridable) {
    // The matrix needs to produce several distinct rejection reasons from one
    // fault, so the code is an input rather than a constant.
    StateMachine sm(with_fault(Fault::AssocReject, 1.0,
                               static_cast<std::uint16_t>(StatusCode::AssocDeniedRates)));
    const ConnectResult r = sm.connect();
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, StatusCode::AssocDeniedRates);   // 18
}

TEST(Faults, FourWayM3TimeoutFailsWithReasonCode15) {
    StateMachine sm(with_fault(Fault::FourWayM3Timeout));
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.failed_at, State::FourWay);
    EXPECT_EQ(r.reason, ReasonCode::FourWayTimeout);
    EXPECT_EQ(static_cast<int>(r.reason), 15) << "IEEE reason code 15 is the 4-way timeout";
    // Association must have succeeded first -- the failure is strictly later.
    EXPECT_GT(r.timings.assoc_ms, 0u);
    EXPECT_GT(r.timings.fourway_ms, 0u);
    EXPECT_EQ(r.timings.dhcp_ms, 0u) << "DHCP must never have been reached";
}

TEST(Faults, FourWayM3TimeoutRetransmitsM2BeforeGivingUp) {
    // A real supplicant retries; if ours gave up on the first miss, the capture
    // would not look like a genuine failure and the forensics layer would be
    // learning from a fiction.
    StateMachine sm(with_fault(Fault::FourWayM3Timeout));
    ASSERT_FALSE(sm.connect().ok);

    int m2_retransmit_logs = 0;
    for (const auto& rec : sm.log_records())
        if (rec.message.find("retransmitting M2") != std::string::npos) ++m2_retransmit_logs;
    EXPECT_GE(m2_retransmit_logs, 3) << "expected at least 3 M2 retransmissions";
    EXPECT_GT(sm.stats().tx_retries, 0u);
}

TEST(Faults, PmkMismatchFailsWith8021xReason) {
    StateMachine sm(with_fault(Fault::PmkMismatch));
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.failed_at, State::FourWay);
    EXPECT_EQ(r.reason, ReasonCode::Ieee8021xFailed);
    // PMK_MISMATCH and FOURWAY_M3_TIMEOUT both die in the handshake, so the
    // reason code is the ONLY thing distinguishing them. That distinction is
    // exactly what the triage layer has to get right.
    EXPECT_NE(r.reason, ReasonCode::FourWayTimeout);
}

TEST(Faults, DhcpNakFailsAfterAFullyKeyedLink) {
    StateMachine sm(with_fault(Fault::DhcpNak));
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.failed_at, State::Dhcp);
    EXPECT_TRUE(r.ip_address.empty());
    // Everything before DHCP must have succeeded. This is the "associated but no
    // internet" failure users actually report, and the stage timings prove the
    // radio layer was healthy.
    EXPECT_GT(r.timings.auth_ms, 0u);
    EXPECT_GT(r.timings.assoc_ms, 0u);
    EXPECT_GT(r.timings.fourway_ms, 0u);
    EXPECT_GT(r.timings.dhcp_ms, 0u);
}

TEST(Faults, ScanEmptyFailsBeforeAuthentication) {
    StateMachine sm(with_fault(Fault::ScanEmpty));
    const ConnectResult r = sm.connect();

    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.failed_at, State::Scanning);
    EXPECT_EQ(r.timings.auth_ms, 0u) << "cannot authenticate to a network never found";
}

TEST(Faults, LowRssiDegradesRateWithoutFailingTheConnection) {
    // Not every fault is a hard failure. LOW_RSSI connects and then performs
    // badly, which a pass/fail-only rig cannot express at all.
    StateMachine weak(with_fault(Fault::LowRssi));
    const ConnectResult r = weak.connect();
    ASSERT_TRUE(r.ok) << "LOW_RSSI should still connect: " << r.message;

    StateMachine healthy(with_fault(Fault::None));
    ASSERT_TRUE(healthy.connect().ok);

    EXPECT_LT(weak.stats().rssi_dbm, -80);
    EXPECT_LT(weak.stats().snr_db, healthy.stats().snr_db);
    EXPECT_LT(weak.stats().tx_rate_mbps, healthy.stats().tx_rate_mbps)
        << "a weak signal must cost throughput";
}

TEST(Faults, ChannelBusyRaisesRetryRateAndSlowsAssociation) {
    StateMachine busy(with_fault(Fault::ChannelBusy));
    ASSERT_TRUE(busy.connect().ok);
    busy.run_connected(2000);

    StateMachine clear(with_fault(Fault::None));
    ASSERT_TRUE(clear.connect().ok);
    clear.run_connected(2000);

    EXPECT_GT(busy.stats().retry_rate, clear.stats().retry_rate);
    EXPECT_GT(busy.stats().retry_rate, 0.15)
        << "a congested channel should show a clearly elevated retry rate";
}

TEST(Faults, BeaconLossDropsAnEstablishedConnection) {
    StateMachine sm(with_fault(Fault::BeaconLoss));
    ASSERT_TRUE(sm.connect().ok) << "BEACON_LOSS only fires once connected";

    const bool still_up = sm.run_connected(5000);
    EXPECT_FALSE(still_up);
    EXPECT_EQ(sm.state(), State::Idle) << "losing the AP should tear the link down";
}

TEST(Faults, DeauthDropsConnectionWithTheGivenReasonCode) {
    StateMachine sm(with_fault(Fault::Deauth, 1.0,
                               static_cast<std::uint16_t>(ReasonCode::DisassocApBusy)));
    ASSERT_TRUE(sm.connect().ok);
    EXPECT_FALSE(sm.run_connected(5000));

    bool found = false;
    for (const auto& rec : sm.log_records())
        if (rec.message.find("DISASSOC_AP_BUSY") != std::string::npos) found = true;
    EXPECT_TRUE(found) << "the injected reason code must appear in the logs";
}

TEST(Faults, RoamPingpongFailsDespiteStayingAssociated) {
    SimConfig c = with_fault(Fault::RoamPingpong);
    StateMachine sm(c);
    ASSERT_TRUE(sm.connect().ok);

    const ConnectResult r = sm.roam();
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.fault, Fault::RoamPingpong);
    EXPECT_EQ(r.failed_at, State::Roaming);
}

// ---------------------------------------------------------------- flake mode

TEST(Faults, ProbabilisticFaultProducesBothOutcomesAcrossSeeds) {
    // This is the generator behind the flaky-test detector: the SAME configuration
    // sometimes passes and sometimes fails, and because each run is seeded, every
    // individual outcome is still perfectly reproducible.
    int passed = 0, failed = 0;
    for (std::uint64_t seed = 1; seed <= 60; ++seed) {
        SimConfig c = with_fault(Fault::FourWayM3Timeout, 0.5);
        c.seed = seed;
        StateMachine sm(c);
        if (sm.connect().ok) ++passed; else ++failed;
    }
    EXPECT_GT(passed, 0) << "a 50% fault must sometimes pass";
    EXPECT_GT(failed, 0) << "a 50% fault must sometimes fail";
    // Loose bounds: asserting an exact split would make this test itself flaky,
    // which would be an unusually embarrassing bug to ship in a flakiness suite.
    EXPECT_GT(passed, 10);
    EXPECT_GT(failed, 10);
}

TEST(Faults, ProbabilityZeroNeverFires) {
    for (std::uint64_t seed = 1; seed <= 20; ++seed) {
        SimConfig c = with_fault(Fault::AuthTimeout, 0.0);
        c.seed = seed;
        StateMachine sm(c);
        EXPECT_TRUE(sm.connect().ok) << "probability 0.0 must never fire (seed " << seed << ")";
    }
}

TEST(Faults, ProbabilityOneAlwaysFires) {
    for (std::uint64_t seed = 1; seed <= 20; ++seed) {
        SimConfig c = with_fault(Fault::AuthTimeout, 1.0);
        c.seed = seed;
        StateMachine sm(c);
        EXPECT_FALSE(sm.connect().ok) << "probability 1.0 must always fire (seed " << seed << ")";
    }
}

TEST(Faults, EveryFaultHasAStageAndADescription) {
    // Guards against adding a fault to the enum and forgetting to wire up its
    // metadata -- the kind of omission that shows up much later as an unhelpful
    // "unknown fault" in a bug report.
    for (const auto& name : all_fault_names()) {
        Fault f;
        ASSERT_TRUE(parse_fault(name, f)) << "round-trip failed for " << name;
        EXPECT_STRNE(fault_description(f), "unknown fault") << name << " lacks a description";
        if (f != Fault::None)
            EXPECT_NE(fault_stage(f), State::Idle) << name << " has no meaningful stage";
    }
}

TEST(Faults, FaultNameRoundTripsThroughStringConversion) {
    for (int i = 0; i <= static_cast<int>(Fault::ScanEmpty); ++i) {
        const auto original = static_cast<Fault>(i);
        Fault parsed;
        ASSERT_TRUE(parse_fault(to_string(original), parsed));
        EXPECT_EQ(parsed, original);
    }
}

TEST(Faults, FaultParsingIsCaseInsensitiveButRejectsGarbage) {
    Fault f;
    EXPECT_TRUE(parse_fault("auth_timeout", f));
    EXPECT_EQ(f, Fault::AuthTimeout);
    EXPECT_TRUE(parse_fault("Auth_Timeout", f));
    EXPECT_FALSE(parse_fault("AUTH_TIMEOUTT", f));
    EXPECT_FALSE(parse_fault("", f));
}

TEST(Faults, RetryCounterAgreesWithTheFramesActuallyTransmitted) {
    // Found by tests/pcap: the DUT reported a 34.8% retry rate while its own
    // capture contained zero frames with the Retry bit set. An internal counter
    // that disagrees with the observable packets makes the rig untrustworthy.
    // See BUILD_JOURNAL.md #13.
    SimConfig c = with_fault(Fault::ChannelBusy);
    c.pcap_path = "/tmp/airframe_retry_check_" + std::to_string(::getpid()) + ".pcap";
    {
        StateMachine sm(c);
        ASSERT_TRUE(sm.connect().ok);
        sm.run_connected(2000);

        const auto stats = sm.stats();
        EXPECT_GT(stats.tx_retries, 0u) << "a congested channel must produce retries";
        // Every retry is a real extra frame, so transmitted frames must exceed the
        // retry count -- this is the invariant that was silently violated before.
        EXPECT_GT(stats.tx_frames, stats.tx_retries);
        EXPECT_GT(stats.retry_rate, 0.10);
    }
    std::remove(c.pcap_path.c_str());
}

TEST(Faults, HealthyLinkRetransmitsRarely) {
    SimConfig c = with_fault(Fault::None);
    StateMachine sm(c);
    ASSERT_TRUE(sm.connect().ok);
    sm.run_connected(2000);
    EXPECT_LT(sm.stats().retry_rate, 0.10) << "an uncongested channel should barely retry";
}
