#include "airframe/frame.hpp"

#include <cstring>

namespace airframe {
namespace {

void put_u16le(Bytes& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void put_u32le(Bytes& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

void put_u64le(Bytes& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

// EAPOL and the 802.11 body use BIG-endian for some fields and little-endian for
// others. This is a real and notorious source of bugs: the 802.11 MAC header is
// little-endian, but EAPOL (inherited from 802.1X / IETF conventions) is
// big-endian. Mixing them up produces frames that look almost right.
void put_u16be(Bytes& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void put_u64be(Bytes& out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

void append(Bytes& out, const Bytes& more) { out.insert(out.end(), more.begin(), more.end()); }

void append_mac(Bytes& out, const std::uint8_t mac[6]) { out.insert(out.end(), mac, mac + 6); }

// Capability Information field (802.11-2020 clause 9.4.1.4).
std::uint16_t capability_info(Security sec) {
    std::uint16_t cap = 0x0001;              // ESS
    if (sec != Security::Open) cap |= 0x0010;  // Privacy
    cap |= 0x0020;                            // Short Preamble
    cap |= 0x0400;                            // Spectrum Management
    return cap;
}

}  // namespace

// ---------------------------------------------------------------- MAC header

Bytes FrameBuilder::mac_header(FrameType type, std::uint8_t subtype,
                               const std::uint8_t addr1[6],
                               const std::uint8_t addr2[6],
                               const std::uint8_t addr3[6],
                               std::uint16_t seq,
                               bool retry,
                               bool protected_frame) {
    Bytes f;
    // Frame Control byte 0: version (bits 0-1) | type (2-3) | subtype (4-7)
    const std::uint8_t fc0 = static_cast<std::uint8_t>(
        (static_cast<std::uint8_t>(subtype) << 4) |
        (static_cast<std::uint8_t>(type) << 2) | 0x00);
    // Frame Control byte 1: flags
    std::uint8_t fc1 = 0;
    if (retry)           fc1 |= 0x08;
    if (protected_frame) fc1 |= 0x40;

    f.push_back(fc0);
    f.push_back(fc1);
    put_u16le(f, 314);          // Duration/ID — a plausible NAV value in microseconds
    append_mac(f, addr1);       // receiver
    append_mac(f, addr2);       // transmitter
    append_mac(f, addr3);       // BSSID (for most management frames)
    // Sequence Control: fragment number (bits 0-3) | sequence number (bits 4-15)
    put_u16le(f, static_cast<std::uint16_t>((seq & 0x0FFF) << 4));
    return f;
}

// ---------------------------------------------------------------- elements

Bytes FrameBuilder::element(ElementId id, const Bytes& data) {
    Bytes e;
    e.push_back(static_cast<std::uint8_t>(id));
    e.push_back(static_cast<std::uint8_t>(data.size()));
    append(e, data);
    return e;
}

Bytes FrameBuilder::ssid_element(const std::string& ssid) {
    Bytes d(ssid.begin(), ssid.end());
    if (d.size() > 32) d.resize(32);   // SSID is capped at 32 octets by spec
    return element(ElementId::Ssid, d);
}

Bytes FrameBuilder::rates_element(Phy phy) {
    // Rates in 500 kbps units; high bit set means "basic" (mandatory) rate.
    Bytes d;
    if (phy == Phy::Dot11n) {
        d = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};  // 1,2,5.5,11 basic + OFDM
    } else {
        d = {0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c};  // 6,9,12,18,24,36,48,54
    }
    return element(ElementId::SupportedRates, d);
}

Bytes FrameBuilder::ds_param_element(std::uint8_t channel) {
    return element(ElementId::DsParameterSet, Bytes{channel});
}

Bytes FrameBuilder::rsn_element(Security security) {
    if (security == Security::Open) return {};   // no RSN IE in an open network

    Bytes d;
    put_u16le(d, 1);                              // RSN version

    // Suite selectors are OUI 00-0F-AC followed by a suite type.
    const std::uint8_t oui[3] = {0x00, 0x0F, 0xAC};

    // Group cipher: CCMP-128 (4)
    d.insert(d.end(), oui, oui + 3);
    d.push_back(0x04);

    // Pairwise cipher list: one entry, CCMP-128
    put_u16le(d, 1);
    d.insert(d.end(), oui, oui + 3);
    d.push_back(0x04);

    // AKM suite list: one entry, varying by security mode
    put_u16le(d, 1);
    d.insert(d.end(), oui, oui + 3);
    switch (security) {
        case Security::Wpa2Psk:        d.push_back(0x02); break;  // PSK
        case Security::Wpa3Sae:        d.push_back(0x08); break;  // SAE
        case Security::Wpa2Enterprise: d.push_back(0x01); break;  // 802.1X
        case Security::Open:           d.push_back(0x00); break;  // unreachable
    }

    // RSN Capabilities. WPA3 mandates Management Frame Protection (bit 6 =
    // MFP-Required, bit 7 = MFP-Capable); WPA2-PSK advertises capable only.
    std::uint16_t rsn_caps = 0x0000;
    if (security == Security::Wpa3Sae) rsn_caps |= 0x00C0;
    else                               rsn_caps |= 0x0080;
    put_u16le(d, rsn_caps);

    return element(ElementId::Rsn, d);
}

Bytes FrameBuilder::ht_capabilities_element() {
    Bytes d(26, 0x00);
    d[0] = 0x2d; d[1] = 0x01;      // HT capability info: 40MHz, SGI
    d[2] = 0x1b;                    // A-MPDU parameters
    d[3] = 0xff; d[4] = 0xff;      // Supported MCS set: MCS 0-15
    return element(ElementId::HtCapabilities, d);
}

Bytes FrameBuilder::vht_capabilities_element() {
    Bytes d;
    put_u32le(d, 0x0f815832);       // VHT capability info: 80MHz, SGI, MU-beamformee
    put_u16le(d, 0xfffa);           // RX MCS map
    put_u16le(d, 0x0000);           // RX highest rate
    put_u16le(d, 0xfffa);           // TX MCS map
    put_u16le(d, 0x0000);           // TX highest rate
    return element(ElementId::VhtCapabilities, d);
}

Bytes FrameBuilder::he_capabilities_element() {
    // HE lives inside the Extended Element (255) with Element ID Extension 35.
    Bytes d;
    d.push_back(35);                                  // Ext ID: HE Capabilities
    const std::uint8_t mac_caps[6] = {0x09, 0x01, 0x00, 0x02, 0x40, 0x00};
    d.insert(d.end(), mac_caps, mac_caps + 6);
    const std::uint8_t phy_caps[11] = {0x42, 0x00, 0x1d, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00};
    d.insert(d.end(), phy_caps, phy_caps + 11);
    put_u16le(d, 0xfffa);                             // RX HE-MCS map <= 80MHz
    put_u16le(d, 0xfffa);                             // TX HE-MCS map <= 80MHz
    return element(ElementId::ExtendedElement, d);
}

Bytes FrameBuilder::phy_capability_elements(Phy phy) {
    Bytes out;
    // Capability elements are cumulative in reality: an 802.11ax AP still
    // advertises HT and VHT so that older clients can associate. Emitting only
    // the newest element is a classic synthetic-capture tell.
    if (phy == Phy::Dot11n || phy == Phy::Dot11ac || phy == Phy::Dot11ax || phy == Phy::Dot11be)
        append(out, ht_capabilities_element());
    if (phy == Phy::Dot11ac || phy == Phy::Dot11ax || phy == Phy::Dot11be)
        append(out, vht_capabilities_element());
    if (phy == Phy::Dot11ax || phy == Phy::Dot11be)
        append(out, he_capabilities_element());
    return out;
}

// ---------------------------------------------------------------- management

Bytes FrameBuilder::beacon(const BssDescriptor& bss, const std::uint8_t sta[6],
                           std::uint16_t seq, std::uint64_t tsf_us) {
    (void)sta;
    const std::uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::Beacon),
                         broadcast, bss.bssid, bss.bssid, seq);
    put_u64le(f, tsf_us);                       // Timestamp (TSF)
    put_u16le(f, 100);                          // Beacon interval: 100 TU = ~102.4ms
    put_u16le(f, capability_info(bss.security));
    append(f, ssid_element(bss.ssid));
    append(f, rates_element(bss.phy));
    append(f, ds_param_element(bss.channel));
    append(f, rsn_element(bss.security));
    append(f, phy_capability_elements(bss.phy));
    return f;
}

Bytes FrameBuilder::probe_request(const std::uint8_t sta[6], const std::string& ssid,
                                  std::uint16_t seq) {
    const std::uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::ProbeRequest),
                         broadcast, sta, broadcast, seq);
    append(f, ssid_element(ssid));
    append(f, rates_element(Phy::Dot11ax));
    return f;
}

Bytes FrameBuilder::probe_response(const BssDescriptor& bss, const std::uint8_t sta[6],
                                   std::uint16_t seq, std::uint64_t tsf_us) {
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::ProbeResponse),
                         sta, bss.bssid, bss.bssid, seq);
    put_u64le(f, tsf_us);
    put_u16le(f, 100);
    put_u16le(f, capability_info(bss.security));
    append(f, ssid_element(bss.ssid));
    append(f, rates_element(bss.phy));
    append(f, ds_param_element(bss.channel));
    append(f, rsn_element(bss.security));
    append(f, phy_capability_elements(bss.phy));
    return f;
}

Bytes FrameBuilder::authentication(const std::uint8_t bssid[6], const std::uint8_t sta[6],
                                   std::uint16_t algo, std::uint16_t seq_num,
                                   StatusCode status, std::uint16_t seq, bool from_ap) {
    const std::uint8_t* a1 = from_ap ? sta : bssid;
    const std::uint8_t* a2 = from_ap ? bssid : sta;
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::Authentication),
                         a1, a2, bssid, seq);
    put_u16le(f, algo);        // 0 = Open System, 3 = SAE
    put_u16le(f, seq_num);     // authentication transaction sequence number
    put_u16le(f, static_cast<std::uint16_t>(status));
    return f;
}

namespace {
// SAE finite cyclic group 19 == NIST P-256. Scalar is 32 octets (the order is
// 256-bit); the element is an uncompressed point, x||y, so 64 octets.
constexpr std::uint16_t kSaeGroupP256 = 19;
}  // namespace

Bytes FrameBuilder::sae_commit(const std::uint8_t bssid[6], const std::uint8_t sta[6],
                               const std::uint8_t scalar[32], const std::uint8_t element[64],
                               std::uint16_t seq, bool from_ap) {
    const std::uint8_t* a1 = from_ap ? sta : bssid;
    const std::uint8_t* a2 = from_ap ? bssid : sta;
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::Authentication),
                         a1, a2, bssid, seq);
    put_u16le(f, 3);   // Authentication Algorithm: SAE
    put_u16le(f, 1);   // Authentication SEQ 1 -> SAE Commit
    put_u16le(f, static_cast<std::uint16_t>(StatusCode::Success));
    put_u16le(f, kSaeGroupP256);
    f.insert(f.end(), scalar, scalar + 32);
    f.insert(f.end(), element, element + 64);
    return f;
}

Bytes FrameBuilder::sae_confirm(const std::uint8_t bssid[6], const std::uint8_t sta[6],
                                std::uint16_t send_confirm, const std::uint8_t confirm[32],
                                std::uint16_t seq, bool from_ap) {
    const std::uint8_t* a1 = from_ap ? sta : bssid;
    const std::uint8_t* a2 = from_ap ? bssid : sta;
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::Authentication),
                         a1, a2, bssid, seq);
    put_u16le(f, 3);   // SAE
    put_u16le(f, 2);   // Authentication SEQ 2 -> SAE Confirm
    put_u16le(f, static_cast<std::uint16_t>(StatusCode::Success));
    put_u16le(f, send_confirm);
    f.insert(f.end(), confirm, confirm + 32);
    return f;
}

Bytes FrameBuilder::assoc_request(const BssDescriptor& bss, const std::uint8_t sta[6],
                                  std::uint16_t seq) {
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::AssocRequest),
                         bss.bssid, sta, bss.bssid, seq);
    put_u16le(f, capability_info(bss.security));
    put_u16le(f, 10);                            // Listen interval
    append(f, ssid_element(bss.ssid));
    append(f, rates_element(bss.phy));
    append(f, rsn_element(bss.security));
    append(f, phy_capability_elements(bss.phy));
    return f;
}

Bytes FrameBuilder::assoc_response(const BssDescriptor& bss, const std::uint8_t sta[6],
                                   StatusCode status, std::uint16_t aid, std::uint16_t seq) {
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::AssocResponse),
                         sta, bss.bssid, bss.bssid, seq);
    put_u16le(f, capability_info(bss.security));
    put_u16le(f, static_cast<std::uint16_t>(status));
    // AID has the two most significant bits set to 1 by convention.
    put_u16le(f, static_cast<std::uint16_t>(aid | 0xC000));
    append(f, rates_element(bss.phy));
    append(f, phy_capability_elements(bss.phy));
    return f;
}

Bytes FrameBuilder::deauthentication(const std::uint8_t dst[6], const std::uint8_t src[6],
                                     const std::uint8_t bssid[6], ReasonCode reason,
                                     std::uint16_t seq) {
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::Deauthentication),
                         dst, src, bssid, seq);
    put_u16le(f, static_cast<std::uint16_t>(reason));
    return f;
}

Bytes FrameBuilder::disassociation(const std::uint8_t dst[6], const std::uint8_t src[6],
                                   const std::uint8_t bssid[6], ReasonCode reason,
                                   std::uint16_t seq) {
    Bytes f = mac_header(FrameType::Management,
                         static_cast<std::uint8_t>(MgmtSubtype::Disassociation),
                         dst, src, bssid, seq);
    put_u16le(f, static_cast<std::uint16_t>(reason));
    return f;
}

// ---------------------------------------------------------------- EAPOL

std::uint16_t eapol::key_info_for(int message, Security security) {
    const std::uint16_t version = (security == Security::Wpa3Sae)
                                      ? kKeyDescVersionAesGcm
                                      : kKeyDescVersionAesHmacSha1;
    switch (message) {
        // M1: AP -> STA. Carries ANonce. No MIC yet (the STA cannot verify one
        // until it derives the PTK, which is the whole point of the handshake).
        case 1: return static_cast<std::uint16_t>(version | kPairwise | kKeyAck);
        // M2: STA -> AP. Carries SNonce + the first MIC.
        case 2: return static_cast<std::uint16_t>(version | kPairwise | kKeyMic);
        // M3: AP -> STA. Install + Ack + MIC + Secure, and the GTK in encrypted
        // key data. This is the message that most often goes missing in the
        // field, and the one our FOURWAY_M3_TIMEOUT fault suppresses.
        case 3: return static_cast<std::uint16_t>(version | kPairwise | kInstall |
                                                  kKeyAck | kKeyMic | kSecure | kEncrypted);
        // M4: STA -> AP. Final acknowledgement.
        case 4: return static_cast<std::uint16_t>(version | kPairwise | kKeyMic | kSecure);
        default: return version;
    }
}

Bytes FrameBuilder::eapol_key(int message,
                              const std::uint8_t dst[6], const std::uint8_t src[6],
                              const std::uint8_t bssid[6],
                              const std::uint8_t nonce[32],
                              std::uint64_t replay_counter,
                              Security security,
                              std::uint16_t seq,
                              bool to_ds) {
    // 802.11 data frame. ToDS/FromDS decide how addr1..3 are interpreted:
    //   STA -> AP (ToDS):   addr1 = BSSID, addr2 = STA,   addr3 = destination
    //   AP -> STA (FromDS): addr1 = STA,   addr2 = BSSID, addr3 = source
    Bytes f;
    const std::uint8_t fc0 = static_cast<std::uint8_t>(
        (0u << 4) | (static_cast<std::uint8_t>(FrameType::Data) << 2));
    std::uint8_t fc1 = to_ds ? 0x01 : 0x02;
    f.push_back(fc0);
    f.push_back(fc1);
    put_u16le(f, 44);
    if (to_ds) { append_mac(f, bssid); append_mac(f, src); append_mac(f, dst); }
    else       { append_mac(f, dst);   append_mac(f, bssid); append_mac(f, src); }
    put_u16le(f, static_cast<std::uint16_t>((seq & 0x0FFF) << 4));

    // LLC/SNAP header announcing EtherType 0x888E (802.1X authentication).
    const std::uint8_t snap[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    f.insert(f.end(), snap, snap + 8);

    // ---- EAPOL header (big-endian from here; see note at top of file) ----
    Bytes body;
    body.push_back(0x02);                 // EAPOL protocol version (802.1X-2004)
    body.push_back(0x03);                 // Packet type: EAPOL-Key
    // Body length is patched in once we know it.
    const std::size_t len_pos = body.size();
    put_u16be(body, 0);

    Bytes kd;
    kd.push_back(0x02);                                        // Descriptor type: RSN
    put_u16be(kd, eapol::key_info_for(message, security));     // Key Information
    put_u16be(kd, 16);                                         // Key Length: CCMP-128
    put_u64be(kd, replay_counter);                             // Replay Counter
    // Key Nonce. M1 carries ANonce, M2 carries SNonce, M3 repeats ANonce,
    // and M4 sends zeros — which is exactly what a real handshake looks like.
    if (message == 4) kd.insert(kd.end(), 32, 0x00);
    else              kd.insert(kd.end(), nonce, nonce + 32);
    kd.insert(kd.end(), 16, 0x00);                             // Key IV
    kd.insert(kd.end(), 8, 0x00);                              // Key RSC
    kd.insert(kd.end(), 8, 0x00);                              // Reserved
    // Key MIC: absent (zeroed) on M1, present on M2-M4. We do not compute a real
    // MIC — that needs the PTK, hence the PMK, hence the passphrase. The frames
    // are structurally correct but not cryptographically valid, which is the
    // right trade-off for a simulator and is documented so nobody is misled.
    if (message == 1) kd.insert(kd.end(), 16, 0x00);
    else              kd.insert(kd.end(), 16, 0xAB);
    // Key Data: M3 carries the encrypted GTK; others carry none.
    if (message == 3) {
        Bytes gtk(56, 0xCD);
        put_u16be(kd, static_cast<std::uint16_t>(gtk.size()));
        kd.insert(kd.end(), gtk.begin(), gtk.end());
    } else {
        put_u16be(kd, 0);
    }

    body.insert(body.end(), kd.begin(), kd.end());
    const std::uint16_t body_len = static_cast<std::uint16_t>(kd.size());
    body[len_pos]     = static_cast<std::uint8_t>((body_len >> 8) & 0xFF);
    body[len_pos + 1] = static_cast<std::uint8_t>(body_len & 0xFF);

    f.insert(f.end(), body.begin(), body.end());
    return f;
}

Bytes FrameBuilder::data_frame(const std::uint8_t dst[6], const std::uint8_t src[6],
                               const std::uint8_t bssid[6], const Bytes& payload,
                               std::uint16_t seq, bool to_ds, bool encrypted,
                               bool retry) {
    Bytes f;
    const std::uint8_t fc0 = static_cast<std::uint8_t>(
        (0u << 4) | (static_cast<std::uint8_t>(FrameType::Data) << 2));
    std::uint8_t fc1 = to_ds ? 0x01 : 0x02;
    if (retry)     fc1 |= 0x08;
    if (encrypted) fc1 |= 0x40;
    f.push_back(fc0);
    f.push_back(fc1);
    put_u16le(f, 44);
    if (to_ds) { append_mac(f, bssid); append_mac(f, src); append_mac(f, dst); }
    else       { append_mac(f, dst);   append_mac(f, bssid); append_mac(f, src); }
    put_u16le(f, static_cast<std::uint16_t>((seq & 0x0FFF) << 4));
    if (encrypted) {
        // CCMP header: PN0, PN1, reserved, KeyID with ExtIV bit, PN2..PN5
        const std::uint8_t ccmp[8] = {0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00};
        f.insert(f.end(), ccmp, ccmp + 8);
    } else {
        const std::uint8_t snap[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
        f.insert(f.end(), snap, snap + 8);
    }
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

}  // namespace airframe
