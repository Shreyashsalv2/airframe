// IEEE 802.11 frame construction.
//
// Builds real, byte-correct management and EAPOL frames so the captures the
// simulator emits can be dissected by Wireshark/Scapy exactly like traffic from a
// real adapter. Everything here follows IEEE 802.11-2020 clause 9 (frame formats).
//
// The MAC header common to management frames:
//
//   +----+----+------+------+------+--------+---------
//   | FC | Dur| Addr1| Addr2| Addr3| SeqCtl | body...
//   +----+----+------+------+------+--------+---------
//     2    2     6      6      6       2
//
// Frame Control's first byte packs version/type/subtype:
//   bits 0-1 protocol version (always 0)
//   bits 2-3 type      (0 = management, 1 = control, 2 = data)
//   bits 4-7 subtype   (8 = beacon, 11 = auth, 0 = assoc req, ...)
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "airframe/types.hpp"

namespace airframe {

using Bytes = std::vector<std::uint8_t>;

enum class FrameType : std::uint8_t { Management = 0, Control = 1, Data = 2 };

enum class MgmtSubtype : std::uint8_t {
    AssocRequest    = 0,
    AssocResponse   = 1,
    ReassocRequest  = 2,
    ReassocResponse = 3,
    ProbeRequest    = 4,
    ProbeResponse   = 5,
    Beacon          = 8,
    Disassociation  = 10,
    Authentication  = 11,
    Deauthentication = 12,
    Action          = 13,
};

// Information Element IDs (802.11-2020 Table 9-128).
enum class ElementId : std::uint8_t {
    Ssid              = 0,
    SupportedRates    = 1,
    DsParameterSet    = 3,
    Tim               = 5,
    Country           = 7,
    HtCapabilities    = 45,
    Rsn               = 48,
    ExtendedRates     = 50,
    HtOperation       = 61,
    RmEnabledCaps     = 70,   // 802.11k
    MobilityDomain    = 54,   // 802.11r
    VhtCapabilities   = 191,
    VhtOperation      = 192,
    ExtendedElement   = 255,  // HE/EHT live behind this with a sub-ID
};

// ---------------------------------------------------------------- builders

class FrameBuilder {
public:
    // Common 802.11 MAC header. `protected_frame` sets the Protected bit, which
    // is what distinguishes encrypted data frames after the 4-way handshake.
    static Bytes mac_header(FrameType type, std::uint8_t subtype,
                            const std::uint8_t addr1[6],
                            const std::uint8_t addr2[6],
                            const std::uint8_t addr3[6],
                            std::uint16_t seq,
                            bool retry = false,
                            bool protected_frame = false);

    // An Information Element: [id][length][data...]
    static Bytes element(ElementId id, const Bytes& data);
    static Bytes ssid_element(const std::string& ssid);
    static Bytes rates_element(Phy phy);
    static Bytes ds_param_element(std::uint8_t channel);
    static Bytes rsn_element(Security security);
    static Bytes ht_capabilities_element();
    static Bytes vht_capabilities_element();
    static Bytes he_capabilities_element();
    static Bytes phy_capability_elements(Phy phy);

    // Management frames
    static Bytes beacon(const BssDescriptor& bss, const std::uint8_t sta[6],
                        std::uint16_t seq, std::uint64_t tsf_us);
    static Bytes probe_request(const std::uint8_t sta[6], const std::string& ssid,
                               std::uint16_t seq);
    static Bytes probe_response(const BssDescriptor& bss, const std::uint8_t sta[6],
                                std::uint16_t seq, std::uint64_t tsf_us);
    static Bytes authentication(const std::uint8_t bssid[6], const std::uint8_t sta[6],
                                std::uint16_t algo, std::uint16_t seq_num,
                                StatusCode status, std::uint16_t seq, bool from_ap);
    // WPA3 uses SAE (Simultaneous Authentication of Equals) instead of Open
    // System auth, and SAE authentication frames carry a real payload. A bare
    // status code with algo=3 is a malformed frame -- Wireshark says so, and it
    // is right. The exchange is four frames: Commit, Commit, Confirm, Confirm.
    //
    //   STA --Commit-->  AP        (group, scalar, element)
    //   STA <--Commit--  AP
    //   STA --Confirm--> AP        (send-confirm counter, confirm hash)
    //   STA <--Confirm-- AP
    //
    // Group 19 is ECP group P-256: a 32-byte scalar and a 64-byte element (x||y).
    static Bytes sae_commit(const std::uint8_t bssid[6], const std::uint8_t sta[6],
                            const std::uint8_t scalar[32], const std::uint8_t element[64],
                            std::uint16_t seq, bool from_ap);
    static Bytes sae_confirm(const std::uint8_t bssid[6], const std::uint8_t sta[6],
                             std::uint16_t send_confirm, const std::uint8_t confirm[32],
                             std::uint16_t seq, bool from_ap);

    static Bytes assoc_request(const BssDescriptor& bss, const std::uint8_t sta[6],
                               std::uint16_t seq);
    static Bytes assoc_response(const BssDescriptor& bss, const std::uint8_t sta[6],
                                StatusCode status, std::uint16_t aid, std::uint16_t seq);
    static Bytes deauthentication(const std::uint8_t dst[6], const std::uint8_t src[6],
                                  const std::uint8_t bssid[6], ReasonCode reason,
                                  std::uint16_t seq);
    static Bytes disassociation(const std::uint8_t dst[6], const std::uint8_t src[6],
                                const std::uint8_t bssid[6], ReasonCode reason,
                                std::uint16_t seq);

    // EAPOL-Key frames carrying the 4-way handshake, as 802.11 data frames with
    // an LLC/SNAP header (ethertype 0x888E).
    // `message` is 1..4 for M1..M4.
    static Bytes eapol_key(int message,
                           const std::uint8_t dst[6], const std::uint8_t src[6],
                           const std::uint8_t bssid[6],
                           const std::uint8_t nonce[32],
                           std::uint64_t replay_counter,
                           Security security,
                           std::uint16_t seq,
                           bool to_ds);

    // A plain encrypted data frame, for post-connection traffic in captures.
    // `retry` sets the Retry bit in Frame Control. A real retransmission ALSO
    // reuses the original sequence number -- that is how a receiver recognises a
    // duplicate. Callers must therefore pass the same `seq` as the original frame.
    static Bytes data_frame(const std::uint8_t dst[6], const std::uint8_t src[6],
                            const std::uint8_t bssid[6], const Bytes& payload,
                            std::uint16_t seq, bool to_ds, bool encrypted,
                            bool retry = false);
};

// Key Info field bit layout for EAPOL-Key (802.11-2020 clause 12.7.2).
namespace eapol {
inline constexpr std::uint16_t kKeyDescVersionAesHmacSha1 = 0x0002;
inline constexpr std::uint16_t kKeyDescVersionAesGcm      = 0x0000;
inline constexpr std::uint16_t kPairwise = 1u << 3;
inline constexpr std::uint16_t kInstall  = 1u << 6;
inline constexpr std::uint16_t kKeyAck   = 1u << 7;
inline constexpr std::uint16_t kKeyMic   = 1u << 8;
inline constexpr std::uint16_t kSecure   = 1u << 9;
inline constexpr std::uint16_t kEncrypted = 1u << 12;

// The canonical key_info values for each handshake message.
std::uint16_t key_info_for(int message, Security security);
}  // namespace eapol

}  // namespace airframe
