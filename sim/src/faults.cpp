#include "airframe/faults.hpp"

#include <algorithm>
#include <cctype>

namespace airframe {
namespace {
std::string upper(const std::string& s) {
    std::string o = s;
    std::transform(o.begin(), o.end(), o.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return o;
}
}  // namespace

const char* to_string(Fault f) noexcept {
    switch (f) {
        case Fault::None:             return "NONE";
        case Fault::AuthTimeout:      return "AUTH_TIMEOUT";
        case Fault::AssocReject:      return "ASSOC_REJECT";
        case Fault::FourWayM3Timeout: return "FOURWAY_M3_TIMEOUT";
        case Fault::PmkMismatch:      return "PMK_MISMATCH";
        case Fault::DhcpNak:          return "DHCP_NAK";
        case Fault::BeaconLoss:       return "BEACON_LOSS";
        case Fault::Deauth:           return "DEAUTH";
        case Fault::LowRssi:          return "LOW_RSSI";
        case Fault::ChannelBusy:      return "CHANNEL_BUSY";
        case Fault::RoamPingpong:     return "ROAM_PINGPONG";
        case Fault::ScanEmpty:        return "SCAN_EMPTY";
    }
    return "UNKNOWN";
}

bool parse_fault(const std::string& in, Fault& out) noexcept {
    const std::string s = upper(in);
    for (int i = 0; i <= static_cast<int>(Fault::ScanEmpty); ++i) {
        const auto f = static_cast<Fault>(i);
        if (s == to_string(f)) { out = f; return true; }
    }
    return false;
}

std::vector<std::string> all_fault_names() {
    std::vector<std::string> names;
    for (int i = 0; i <= static_cast<int>(Fault::ScanEmpty); ++i)
        names.emplace_back(to_string(static_cast<Fault>(i)));
    return names;
}

State fault_stage(Fault f) noexcept {
    switch (f) {
        case Fault::ScanEmpty:        return State::Scanning;
        case Fault::AuthTimeout:      return State::Authenticating;
        case Fault::AssocReject:      return State::Associating;
        case Fault::FourWayM3Timeout:
        case Fault::PmkMismatch:      return State::FourWay;
        case Fault::DhcpNak:          return State::Dhcp;
        case Fault::BeaconLoss:
        case Fault::Deauth:
        case Fault::LowRssi:
        case Fault::ChannelBusy:      return State::Connected;
        case Fault::RoamPingpong:     return State::Roaming;
        case Fault::None:             return State::Idle;
    }
    return State::Idle;
}

StatusCode fault_status_code(Fault f) noexcept {
    switch (f) {
        case Fault::AuthTimeout: return StatusCode::AuthTimeout;
        case Fault::AssocReject: return StatusCode::ApUnableToHandleSta;
        case Fault::PmkMismatch: return StatusCode::InvalidPmkid;
        default:                 return StatusCode::Success;
    }
}

ReasonCode fault_reason_code(Fault f) noexcept {
    switch (f) {
        case Fault::FourWayM3Timeout: return ReasonCode::FourWayTimeout;
        case Fault::PmkMismatch:      return ReasonCode::Ieee8021xFailed;
        case Fault::BeaconLoss:       return ReasonCode::BeaconLoss;
        // NOT DeauthLeaving (3): that code means "the station is leaving", which is
        // exactly what a normal graceful disconnect sends. Using it for an injected
        // fault made a deliberate deauth indistinguishable from a clean shutdown --
        // the clustering layer merged the two, correctly, because they genuinely
        // looked identical. See BUILD_JOURNAL.md #15.
        case Fault::Deauth:           return ReasonCode::Unspecified;
        case Fault::LowRssi:          return ReasonCode::BeaconLoss;
        case Fault::DhcpNak:          return ReasonCode::Unspecified;
        default:                      return ReasonCode::Unspecified;
    }
}

const char* fault_description(Fault f) noexcept {
    switch (f) {
        case Fault::None:
            return "no fault injected";
        case Fault::AuthTimeout:
            return "AP did not respond to the authentication request within the timeout";
        case Fault::AssocReject:
            return "AP rejected the association request with a non-success status code";
        case Fault::FourWayM3Timeout:
            return "4-way handshake stalled after M2; message 3 never arrived from the AP";
        case Fault::PmkMismatch:
            return "PMK mismatch: the pairwise key check failed, usually a wrong passphrase";
        case Fault::DhcpNak:
            return "link established but DHCP server refused the address request";
        case Fault::BeaconLoss:
            return "beacons from the AP stopped arriving; station lost contact";
        case Fault::Deauth:
            return "AP actively deauthenticated the station";
        case Fault::LowRssi:
            return "signal strength fell below the usable threshold";
        case Fault::ChannelBusy:
            return "channel contention drove retries up and throughput down";
        case Fault::RoamPingpong:
            return "station oscillated repeatedly between two BSSIDs in the same ESS";
        case Fault::ScanEmpty:
            return "scan completed but found no networks";
    }
    return "unknown fault";
}

}  // namespace airframe
