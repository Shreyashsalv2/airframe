// airframe — core domain types for the Wi-Fi DUT simulator.
//
// Everything the simulator models lives here as a strongly-typed enum with
// explicit string conversions. Stringly-typed state machines are the classic way
// these programs rot, so states/events/faults are never raw strings internally;
// strings exist only at the boundary (CLI, JSON control protocol, logs).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace airframe {

// ---------------------------------------------------------------- link state
//
// The lifecycle of an 802.11 station associating to an access point. This mirrors
// the real sequence a Wi-Fi client goes through; each state maps to observable
// frames on the air and observable lines in a driver log.
enum class State : std::uint8_t {
    Idle,            // radio up, not connected
    Scanning,        // sending probe requests / listening for beacons
    Authenticating,  // 802.11 Open System or SAE authentication
    Associating,     // association request/response
    FourWay,         // WPA2/WPA3 4-way EAPOL key handshake (M1..M4)
    Dhcp,            // DHCP DORA — has a link, needs an address
    Connected,       // fully usable
    Roaming,         // moving to a different BSS in the same ESS
    Disconnecting,   // tearing down
    Failed,          // terminal error state; holds the reason
};

// Events that drive transitions. Kept separate from State so the transition
// table is a pure function of (state, event) with no hidden inputs.
enum class Event : std::uint8_t {
    ScanStart, ScanDone,
    AuthStart, AuthOk, AuthFail,
    AssocStart, AssocOk, AssocFail,
    FourWayStart, FourWayOk, FourWayFail,
    DhcpStart, DhcpOk, DhcpFail,
    LinkUp,
    RoamStart, RoamOk, RoamFail,
    Deauth, DisconnectReq, Disconnected,
    Reset,
};

enum class Security : std::uint8_t {
    Open,
    Wpa2Psk,
    Wpa3Sae,
    Wpa2Enterprise,
};

enum class Band : std::uint8_t {
    Band2_4GHz,
    Band5GHz,
    Band6GHz,
};

enum class Phy : std::uint8_t {
    Dot11n,   // HT
    Dot11ac,  // VHT
    Dot11ax,  // HE  (Wi-Fi 6 / 6E)
    Dot11be,  // EHT (Wi-Fi 7)
};

// IEEE 802.11 status codes (assoc/auth responses). Subset we actually emit.
enum class StatusCode : std::uint16_t {
    Success                 = 0,
    UnspecifiedFailure      = 1,
    CapabilitiesMismatch    = 10,
    AssocDeniedNoReason     = 12,
    AuthAlgoUnsupported     = 13,
    AuthSeqUnexpected       = 14,
    ChallengeFailure        = 15,
    AuthTimeout             = 16,
    ApUnableToHandleSta     = 17,  // AP at capacity
    AssocDeniedRates        = 18,
    InvalidRsnIeCapab       = 45,
    InvalidPmkid            = 53,
    InvalidAkmp             = 43,
};

// IEEE 802.11 reason codes (deauth/disassoc). Subset we actually emit.
enum class ReasonCode : std::uint16_t {
    Unspecified             = 1,
    PrevAuthNotValid        = 2,
    DeauthLeaving           = 3,
    DisassocInactivity      = 4,
    DisassocApBusy          = 5,
    Class2FrameFromNonAuth  = 6,
    Class3FrameFromNonAssoc = 7,
    DisassocStaLeaving      = 8,
    FourWayTimeout          = 15,  // "4-Way Handshake timeout"
    GroupKeyTimeout         = 16,
    IeMismatch              = 17,
    InvalidGroupCipher      = 18,
    InvalidPairwiseCipher   = 19,
    InvalidAkmp             = 20,
    Ieee8021xFailed         = 23,
    BeaconLoss              = 34,  // vendor-ish; used for "lost contact with AP"
};

// ---------------------------------------------------------------- conversions
const char* to_string(State s) noexcept;
const char* to_string(Event e) noexcept;
const char* to_string(Security s) noexcept;
const char* to_string(Band b) noexcept;
const char* to_string(Phy p) noexcept;
const char* to_string(StatusCode c) noexcept;
const char* to_string(ReasonCode c) noexcept;

bool parse_security(const std::string& in, Security& out) noexcept;
bool parse_band(const std::string& in, Band& out) noexcept;
bool parse_phy(const std::string& in, Phy& out) noexcept;
bool parse_state(const std::string& in, State& out) noexcept;

// ---------------------------------------------------------------- radio facts

// Centre frequency in MHz for a (band, channel) pair. Returns 0 if invalid.
std::uint16_t channel_to_freq(Band band, std::uint8_t channel) noexcept;

// Channel widths legal for a band, narrowest first.
std::vector<std::uint16_t> legal_widths(Band band) noexcept;

// Does this PHY generation exist on this band? 802.11n has no 6GHz; 802.11ac is
// 5GHz-only; 6GHz requires ax or be. Encoding this here rather than in the tests
// means the interop matrix can generate only *valid* combinations.
bool phy_supported_on_band(Phy phy, Band band) noexcept;

// Does this security mode work on this band? 6GHz mandates WPA3 — Open and
// WPA2-PSK are forbidden there by spec. This is a real interop rule and a
// genuinely good source of test cases.
bool security_supported_on_band(Security sec, Band band) noexcept;

// Maximum channel width each PHY generation can negotiate.
//   802.11n  (HT)  : 40 MHz
//   802.11ac (VHT) : 160 MHz
//   802.11ax (HE)  : 160 MHz
//   802.11be (EHT) : 320 MHz
// A station asking for 320 MHz on 802.11ax is not a slow link, it is an
// impossible one, and the DUT must refuse rather than quietly negotiate down.
std::uint16_t max_width_for_phy(Phy phy) noexcept;
bool phy_supports_width(Phy phy, std::uint16_t width_mhz) noexcept;

struct BssDescriptor {
    std::string   ssid;
    std::uint8_t  bssid[6]{};
    Band          band     = Band::Band5GHz;
    std::uint8_t  channel  = 36;
    std::uint16_t width    = 80;
    Phy           phy      = Phy::Dot11ax;
    Security      security = Security::Wpa2Psk;
    int           rssi_dbm = -45;
    int           noise_dbm = -95;

    int snr_db() const noexcept { return rssi_dbm - noise_dbm; }
};

}  // namespace airframe
