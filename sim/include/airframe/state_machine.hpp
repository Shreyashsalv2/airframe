// The 802.11 station state machine — the simulated Device Under Test.
//
// This is the "hardware" the Python test framework drives. It models the real
// association lifecycle closely enough that the logs and captures it emits can be
// analysed with the same techniques you would apply to a genuine Wi-Fi client.
//
//   IDLE ──scan──► SCANNING ──auth──► AUTHENTICATING ──►  ASSOCIATING
//                                                              │
//              ┌───────────────────────────────────────────────┘
//              ▼                    (open network skips the handshake)
//        FOURWAY_HANDSHAKE ──────► DHCP ──────► CONNECTED ⇄ ROAMING
//              │                     │              │
//              └──────► FAILED ◄─────┘              └──► DISCONNECTING ──► IDLE
//
// Three design decisions worth understanding:
//
// 1. THE TRANSITION TABLE IS DATA, NOT CONTROL FLOW. Legal transitions live in a
//    lookup table rather than in nested if/else. An illegal transition throws
//    rather than silently doing nothing, so a bug in the driver surfaces
//    immediately instead of leaving the DUT in a quietly wrong state.
//
// 2. NO WALL-CLOCK SLEEPING. Every delay advances a VirtualClock. A full
//    connection that "takes" 2.4 seconds completes in microseconds, and takes
//    exactly the same time on a loaded machine as on an idle one.
//
// 3. FAULTS ARE CHECKED AT STAGE BOUNDARIES. Each stage asks "is my fault
//    active?" before proceeding, which keeps fault handling in one place per
//    stage instead of scattered through the logic.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "airframe/faults.hpp"
#include "airframe/frame.hpp"
#include "airframe/logger.hpp"
#include "airframe/pcap_writer.hpp"
#include "airframe/rng.hpp"
#include "airframe/types.hpp"

namespace airframe {

// Thrown when the driver asks for a transition the table forbids. Carries both
// halves of the illegal pair so the message is actionable on its own.
class IllegalTransition : public std::logic_error {
public:
    IllegalTransition(State from, Event ev)
        : std::logic_error(std::string("illegal transition: ") + to_string(from) +
                           " --" + to_string(ev) + "-->"),
          from_(from), event_(ev) {}

    State from()  const noexcept { return from_; }
    Event event() const noexcept { return event_; }

private:
    State from_;
    Event event_;
};

struct StageTimings {
    std::uint64_t scan_ms    = 0;
    std::uint64_t auth_ms    = 0;
    std::uint64_t assoc_ms   = 0;
    std::uint64_t fourway_ms = 0;
    std::uint64_t dhcp_ms    = 0;
    std::uint64_t total_ms   = 0;
};

struct ConnectResult {
    bool          ok          = false;
    State         final_state = State::Idle;
    Fault         fault       = Fault::None;
    StatusCode    status      = StatusCode::Success;
    ReasonCode    reason      = ReasonCode::Unspecified;
    State         failed_at   = State::Idle;
    StageTimings  timings;
    std::string   message;
    std::string   bssid;
    std::string   ip_address;

    std::string to_json() const;
};

struct LinkStats {
    int           rssi_dbm     = 0;
    int           noise_dbm    = -95;
    int           snr_db       = 0;
    std::uint8_t  channel      = 0;
    std::uint16_t width_mhz    = 0;
    std::uint32_t tx_rate_mbps = 0;
    std::uint64_t tx_frames    = 0;
    std::uint64_t rx_frames    = 0;
    std::uint64_t tx_retries   = 0;
    double        retry_rate   = 0.0;

    std::string to_json() const;
};

struct ScanEntry {
    std::string   ssid;
    std::string   bssid;
    Band          band     = Band::Band5GHz;
    std::uint8_t  channel  = 36;
    std::uint16_t width    = 80;
    Phy           phy      = Phy::Dot11ax;
    Security      security = Security::Wpa2Psk;
    int           rssi_dbm = -50;
};

struct SimConfig {
    std::string   ssid     = "airframe-test-ap";
    Security      security = Security::Wpa2Psk;
    Band          band     = Band::Band5GHz;
    std::uint8_t  channel  = 36;
    std::uint16_t width    = 80;
    Phy           phy      = Phy::Dot11ax;
    std::uint64_t seed     = 42;
    FaultSpec     fault;
    std::string   log_path;
    std::string   pcap_path;
    bool          log_stderr = false;
};

class StateMachine {
public:
    explicit StateMachine(SimConfig config);
    ~StateMachine();

    StateMachine(const StateMachine&)            = delete;
    StateMachine& operator=(const StateMachine&) = delete;

    // ---- transition table (pure, static, testable in isolation) ----
    static bool  is_legal(State from, Event ev) noexcept;
    static State next_state(State from, Event ev);   // throws IllegalTransition
    static const std::map<std::pair<State, Event>, State>& table();

    // ---- observation ----
    State        state()  const noexcept { return state_; }
    LinkStats    stats()  const;
    const SimConfig& config() const noexcept { return config_; }
    std::uint64_t now_ms() const noexcept { return clock_.now_ms(); }
    const std::vector<LogRecord>& log_records() const { return logger_.records(); }
    std::uint64_t frames_captured() const noexcept { return pcap_.frames_written(); }
    std::string  bssid_string() const { return mac_to_string(bssid_); }

    // ---- operations (each drives the machine through several transitions) ----
    std::vector<ScanEntry> scan();
    ConnectResult          connect();
    ConnectResult          roam();
    void                   disconnect(ReasonCode reason = ReasonCode::DeauthLeaving);
    void                   reset();

    // Simulate `ms` of connected operation, accumulating traffic statistics and
    // honouring any connected-state fault. Returns false if the link dropped.
    bool run_connected(std::uint64_t ms);

    // Change the injected fault at runtime (used by the TCP control protocol).
    void set_fault(const FaultSpec& spec) noexcept { config_.fault = spec; }

    std::string session_summary_json() const;

private:
    // Drives one transition, logging it. Throws on an illegal pair.
    void transition(Event ev, const std::string& why = "");

    // Fault gating: does the configured fault fire for this stage right now?
    bool fault_fires(Fault f) noexcept;

    void log(LogLevel level, const std::string& component, const std::string& message);
    void emit(const Bytes& frame, bool from_ap, bool bad_fcs = false);
    void advance(std::uint64_t ms) { clock_.advance(ms); }

    void build_bss();
    RadioInfo radio_now(bool bad_fcs) const;

    SimConfig     config_;
    State         state_ = State::Idle;
    Rng           rng_;
    VirtualClock  clock_;
    Logger        logger_;
    PcapWriter    pcap_;

    BssDescriptor bss_;
    std::uint8_t  sta_[6]{};
    std::uint8_t  bssid_[6]{};
    std::uint8_t  bssid_alt_[6]{};    // second BSS in the ESS, for roaming
    std::uint16_t seq_ = 0;
    std::uint64_t replay_counter_ = 1;

    int           rssi_dbm_   = -45;
    std::uint64_t tx_frames_  = 0;
    std::uint64_t rx_frames_  = 0;
    std::uint64_t tx_retries_ = 0;
    std::string   ip_address_;
    ConnectResult last_result_;
    std::vector<std::string> transition_history_;
};

}  // namespace airframe
