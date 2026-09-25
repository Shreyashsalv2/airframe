#include "airframe/types.hpp"

#include <algorithm>
#include <cctype>

namespace airframe {
namespace {
std::string lower(const std::string& s) {
    std::string o = s;
    std::transform(o.begin(), o.end(), o.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return o;
}
}  // namespace

const char* to_string(State s) noexcept {
    switch (s) {
        case State::Idle:           return "IDLE";
        case State::Scanning:       return "SCANNING";
        case State::Authenticating: return "AUTHENTICATING";
        case State::Associating:    return "ASSOCIATING";
        case State::FourWay:        return "FOURWAY_HANDSHAKE";
        case State::Dhcp:           return "DHCP";
        case State::Connected:      return "CONNECTED";
        case State::Roaming:        return "ROAMING";
        case State::Disconnecting:  return "DISCONNECTING";
        case State::Failed:         return "FAILED";
    }
    return "UNKNOWN";
}

const char* to_string(Event e) noexcept {
    switch (e) {
        case Event::ScanStart:     return "SCAN_START";
        case Event::ScanDone:      return "SCAN_DONE";
        case Event::AuthStart:     return "AUTH_START";
        case Event::AuthOk:        return "AUTH_OK";
        case Event::AuthFail:      return "AUTH_FAIL";
        case Event::AssocStart:    return "ASSOC_START";
        case Event::AssocOk:       return "ASSOC_OK";
        case Event::AssocFail:     return "ASSOC_FAIL";
        case Event::FourWayStart:  return "FOURWAY_START";
        case Event::FourWayOk:     return "FOURWAY_OK";
        case Event::FourWayFail:   return "FOURWAY_FAIL";
        case Event::DhcpStart:     return "DHCP_START";
        case Event::DhcpOk:        return "DHCP_OK";
        case Event::DhcpFail:      return "DHCP_FAIL";
        case Event::LinkUp:        return "LINK_UP";
        case Event::RoamStart:     return "ROAM_START";
        case Event::RoamOk:        return "ROAM_OK";
        case Event::RoamFail:      return "ROAM_FAIL";
        case Event::Deauth:        return "DEAUTH";
        case Event::DisconnectReq: return "DISCONNECT_REQ";
        case Event::Disconnected:  return "DISCONNECTED";
        case Event::Reset:         return "RESET";
    }
    return "UNKNOWN";
}

const char* to_string(Security s) noexcept {
    switch (s) {
        case Security::Open:           return "open";
        case Security::Wpa2Psk:        return "wpa2_psk";
        case Security::Wpa3Sae:        return "wpa3_sae";
        case Security::Wpa2Enterprise: return "wpa2_enterprise";
    }
    return "unknown";
}

const char* to_string(Band b) noexcept {
    switch (b) {
        case Band::Band2_4GHz: return "2.4GHz";
        case Band::Band5GHz:   return "5GHz";
        case Band::Band6GHz:   return "6GHz";
    }
    return "unknown";
}

const char* to_string(Phy p) noexcept {
    switch (p) {
        case Phy::Dot11n:  return "11n";
        case Phy::Dot11ac: return "11ac";
        case Phy::Dot11ax: return "11ax";
        case Phy::Dot11be: return "11be";
    }
    return "unknown";
}

const char* to_string(StatusCode c) noexcept {
    switch (c) {
        case StatusCode::Success:              return "SUCCESS";
        case StatusCode::UnspecifiedFailure:   return "UNSPECIFIED_FAILURE";
        case StatusCode::CapabilitiesMismatch: return "CAPABILITIES_MISMATCH";
        case StatusCode::AssocDeniedNoReason:  return "ASSOC_DENIED_NO_REASON";
        case StatusCode::AuthAlgoUnsupported:  return "AUTH_ALGO_UNSUPPORTED";
        case StatusCode::AuthSeqUnexpected:    return "AUTH_SEQ_UNEXPECTED";
        case StatusCode::ChallengeFailure:     return "CHALLENGE_FAILURE";
        case StatusCode::AuthTimeout:          return "AUTH_TIMEOUT";
        case StatusCode::ApUnableToHandleSta:  return "AP_UNABLE_TO_HANDLE_STA";
        case StatusCode::AssocDeniedRates:     return "ASSOC_DENIED_RATES";
        case StatusCode::InvalidRsnIeCapab:    return "INVALID_RSN_IE_CAPABILITIES";
        case StatusCode::InvalidPmkid:         return "INVALID_PMKID";
        case StatusCode::InvalidAkmp:          return "INVALID_AKMP";
    }
    return "STATUS_UNKNOWN";
}

const char* to_string(ReasonCode c) noexcept {
    switch (c) {
        case ReasonCode::Unspecified:             return "UNSPECIFIED";
        case ReasonCode::PrevAuthNotValid:        return "PREV_AUTH_NOT_VALID";
        case ReasonCode::DeauthLeaving:           return "DEAUTH_LEAVING";
        case ReasonCode::DisassocInactivity:      return "DISASSOC_INACTIVITY";
        case ReasonCode::DisassocApBusy:          return "DISASSOC_AP_BUSY";
        case ReasonCode::Class2FrameFromNonAuth:  return "CLASS2_FRAME_FROM_NONAUTH";
        case ReasonCode::Class3FrameFromNonAssoc: return "CLASS3_FRAME_FROM_NONASSOC";
        case ReasonCode::DisassocStaLeaving:      return "DISASSOC_STA_LEAVING";
        case ReasonCode::FourWayTimeout:          return "FOURWAY_HANDSHAKE_TIMEOUT";
        case ReasonCode::GroupKeyTimeout:         return "GROUP_KEY_TIMEOUT";
        case ReasonCode::IeMismatch:              return "IE_MISMATCH";
        case ReasonCode::InvalidGroupCipher:      return "INVALID_GROUP_CIPHER";
        case ReasonCode::InvalidPairwiseCipher:   return "INVALID_PAIRWISE_CIPHER";
        case ReasonCode::InvalidAkmp:             return "INVALID_AKMP";
        case ReasonCode::Ieee8021xFailed:         return "IEEE8021X_FAILED";
        case ReasonCode::BeaconLoss:              return "BEACON_LOSS";
    }
    return "REASON_UNKNOWN";
}

bool parse_security(const std::string& in, Security& out) noexcept {
    const std::string s = lower(in);
    if (s == "open" || s == "none")                          { out = Security::Open; return true; }
    if (s == "wpa2_psk" || s == "wpa2" || s == "psk")        { out = Security::Wpa2Psk; return true; }
    if (s == "wpa3_sae" || s == "wpa3" || s == "sae")        { out = Security::Wpa3Sae; return true; }
    if (s == "wpa2_enterprise" || s == "enterprise" || s == "eap") {
        out = Security::Wpa2Enterprise; return true;
    }
    return false;
}

bool parse_band(const std::string& in, Band& out) noexcept {
    const std::string s = lower(in);
    if (s == "2.4ghz" || s == "2.4" || s == "2g") { out = Band::Band2_4GHz; return true; }
    if (s == "5ghz"   || s == "5"   || s == "5g") { out = Band::Band5GHz;   return true; }
    if (s == "6ghz"   || s == "6"   || s == "6g") { out = Band::Band6GHz;   return true; }
    return false;
}

bool parse_phy(const std::string& in, Phy& out) noexcept {
    const std::string s = lower(in);
    if (s == "11n"  || s == "n")  { out = Phy::Dot11n;  return true; }
    if (s == "11ac" || s == "ac") { out = Phy::Dot11ac; return true; }
    if (s == "11ax" || s == "ax") { out = Phy::Dot11ax; return true; }
    if (s == "11be" || s == "be") { out = Phy::Dot11be; return true; }
    return false;
}

bool parse_state(const std::string& in, State& out) noexcept {
    for (int i = 0; i <= static_cast<int>(State::Failed); ++i) {
        const auto s = static_cast<State>(i);
        if (in == to_string(s)) { out = s; return true; }
    }
    return false;
}

std::uint16_t channel_to_freq(Band band, std::uint8_t channel) noexcept {
    switch (band) {
        case Band::Band2_4GHz:
            if (channel >= 1 && channel <= 13)
                return static_cast<std::uint16_t>(2407 + 5 * channel);
            if (channel == 14) return 2484;   // Japan-only, and genuinely special-cased
            return 0;
        case Band::Band5GHz:
            if (channel >= 36 && channel <= 177)
                return static_cast<std::uint16_t>(5000 + 5 * channel);
            return 0;
        case Band::Band6GHz:
            // 6 GHz channel 1 is centred at 5955 MHz, spaced 5 MHz apart.
            if (channel >= 1 && channel <= 233)
                return static_cast<std::uint16_t>(5950 + 5 * channel);
            return 0;
    }
    return 0;
}

std::vector<std::uint16_t> legal_widths(Band band) noexcept {
    switch (band) {
        case Band::Band2_4GHz: return {20, 40};
        case Band::Band5GHz:   return {20, 40, 80, 160};
        case Band::Band6GHz:   return {20, 40, 80, 160, 320};
    }
    return {20};
}

bool phy_supported_on_band(Phy phy, Band band) noexcept {
    switch (phy) {
        case Phy::Dot11n:  return band != Band::Band6GHz;                 // HT: 2.4 + 5 only
        case Phy::Dot11ac: return band == Band::Band5GHz;                 // VHT: 5 GHz only
        case Phy::Dot11ax: return true;                                   // HE: all three
        case Phy::Dot11be: return true;                                   // EHT: all three
    }
    return false;
}

std::uint16_t max_width_for_phy(Phy phy) noexcept {
    switch (phy) {
        case Phy::Dot11n:  return 40;    // HT tops out at 40 MHz
        case Phy::Dot11ac: return 160;   // VHT adds 80 and 160
        case Phy::Dot11ax: return 160;   // HE matches VHT on width
        case Phy::Dot11be: return 320;   // EHT introduces 320 MHz
    }
    return 20;
}

bool phy_supports_width(Phy phy, std::uint16_t width_mhz) noexcept {
    return width_mhz <= max_width_for_phy(phy);
}

bool security_supported_on_band(Security sec, Band band) noexcept {
    // 6 GHz mandates WPA3 (SAE) and forbids Open and WPA2-PSK outright —
    // IEEE 802.11ax / Wi-Fi Alliance 6E requirement. A real interop rule, and a
    // genuinely good source of negative test cases.
    if (band == Band::Band6GHz)
        return sec == Security::Wpa3Sae || sec == Security::Wpa2Enterprise;
    return true;
}

}  // namespace airframe
