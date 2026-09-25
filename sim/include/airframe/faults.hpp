// Fault injection.
//
// A test rig that can only observe the happy path is worth very little. Real
// wireless QA is almost entirely about what happens when things go wrong, so the
// simulator can be told to fail in specific, named, reproducible ways.
//
// Two flavours:
//   * DETERMINISTIC faults always fire. Used to assert "when X breaks, the system
//     reports X" — the backbone of the connectivity suite.
//   * PROBABILISTIC flake mode fires with probability p. Used to generate genuine
//     intermittent failures, which is what the flaky-test detector is trained on.
//     Because the RNG is seeded, even the "random" failures replay exactly.
#pragma once

#include <string>
#include <vector>

#include "airframe/types.hpp"

namespace airframe {

enum class Fault : std::uint8_t {
    None = 0,
    AuthTimeout,        // AP never answers the authentication frame
    AssocReject,        // AP answers association with a non-zero status code
    FourWayM3Timeout,   // handshake stalls after M2 — M3 never arrives
    PmkMismatch,        // wrong passphrase: MIC check fails at M2/M3
    DhcpNak,            // associated and keyed, but no IP address
    BeaconLoss,         // AP stops beaconing while connected
    Deauth,             // AP actively deauthenticates the station
    LowRssi,            // signal collapses below the usable floor
    ChannelBusy,        // heavy contention: everything gets slower, retries climb
    RoamPingpong,       // station oscillates between two BSSes
    ScanEmpty,          // scan returns no networks at all
};

struct FaultSpec {
    Fault       fault       = Fault::None;
    double      probability = 1.0;   // 1.0 = deterministic, <1.0 = flake mode
    std::uint16_t code      = 0;     // status/reason code override; 0 = use default

    bool active() const noexcept { return fault != Fault::None; }
};

const char* to_string(Fault f) noexcept;
bool parse_fault(const std::string& in, Fault& out) noexcept;
std::vector<std::string> all_fault_names();

// Which stage of the connection lifecycle a fault manifests in. Used to decide
// where in the state machine to check for it, and to tell the analysis layers
// which stage to blame.
State fault_stage(Fault f) noexcept;

// The IEEE status code a given fault should produce, when it produces one.
StatusCode fault_status_code(Fault f) noexcept;

// The IEEE reason code a given fault should produce, when it produces one.
ReasonCode fault_reason_code(Fault f) noexcept;

// A one-line human-readable explanation. This is what shows up in the failure
// message, and what the triage agent is ultimately scored against.
const char* fault_description(Fault f) noexcept;

}  // namespace airframe
