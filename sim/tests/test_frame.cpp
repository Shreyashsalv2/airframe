// Tests for 802.11 frame construction, at the byte level where it counts.

#include <gtest/gtest.h>

#include "airframe/frame.hpp"

using namespace airframe;

namespace {
const std::uint8_t kBssid[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
const std::uint8_t kSta[6]   = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

std::uint16_t u16le(const Bytes& b, std::size_t off) {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(b[off]) |
                                      (static_cast<std::uint16_t>(b[off + 1]) << 8));
}
std::uint16_t u16be(const Bytes& b, std::size_t off) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(b[off]) << 8) |
                                      static_cast<std::uint16_t>(b[off + 1]));
}

BssDescriptor bss(Security sec = Security::Wpa2Psk, Phy phy = Phy::Dot11ax) {
    BssDescriptor b;
    b.ssid = "unit-test-ap";
    std::memcpy(b.bssid, kBssid, 6);
    b.security = sec;
    b.phy      = phy;
    b.channel  = 36;
    return b;
}
}  // namespace

TEST(FrameHeader, FrameControlPacksTypeAndSubtype) {
    const Bytes f = FrameBuilder::mac_header(FrameType::Management,
                                             static_cast<std::uint8_t>(MgmtSubtype::Beacon),
                                             kSta, kBssid, kBssid, 0);
    // byte 0 = subtype<<4 | type<<2 | version. Beacon(8), Management(0), v0 = 0x80
    EXPECT_EQ(f[0], 0x80);
    EXPECT_EQ(f[1], 0x00) << "no flags set";
    EXPECT_EQ(f.size(), 24u) << "a management MAC header is 24 bytes";
}

TEST(FrameHeader, AuthenticationSubtypeIsEleven) {
    const Bytes f = FrameBuilder::authentication(kBssid, kSta, 0, 1, StatusCode::Success, 0, false);
    EXPECT_EQ((f[0] >> 4) & 0x0F, 11) << "Authentication is subtype 11";
    EXPECT_EQ((f[0] >> 2) & 0x03, 0)  << "Management frame type";
}

TEST(FrameHeader, RetryAndProtectedFlagsAreSettable) {
    const Bytes retry = FrameBuilder::mac_header(FrameType::Data, 0, kSta, kBssid, kBssid, 0,
                                                 /*retry=*/true, /*protected=*/false);
    EXPECT_EQ(retry[1] & 0x08, 0x08) << "retry bit";

    const Bytes prot = FrameBuilder::mac_header(FrameType::Data, 0, kSta, kBssid, kBssid, 0,
                                                false, /*protected=*/true);
    EXPECT_EQ(prot[1] & 0x40, 0x40) << "protected bit";
}

TEST(FrameHeader, SequenceNumberOccupiesTheUpperTwelveBits) {
    const Bytes f = FrameBuilder::mac_header(FrameType::Management, 8, kSta, kBssid, kBssid, 0x123);
    // Sequence Control: fragment number in bits 0-3, sequence number in bits 4-15.
    EXPECT_EQ(u16le(f, 22) >> 4, 0x123u);
    EXPECT_EQ(u16le(f, 22) & 0x0F, 0u) << "fragment number is 0";
}

TEST(Elements, SsidElementCarriesIdAndLength) {
    const Bytes e = FrameBuilder::ssid_element("hello");
    EXPECT_EQ(e[0], 0)  << "SSID element ID is 0";
    EXPECT_EQ(e[1], 5)  << "length";
    EXPECT_EQ(std::string(e.begin() + 2, e.end()), "hello");
}

TEST(Elements, SsidIsTruncatedToThirtyTwoOctets) {
    const Bytes e = FrameBuilder::ssid_element(std::string(60, 'x'));
    EXPECT_EQ(e[1], 32) << "802.11 caps the SSID at 32 octets";
    EXPECT_EQ(e.size(), 34u);
}

TEST(Elements, OpenNetworkHasNoRsnElement) {
    EXPECT_TRUE(FrameBuilder::rsn_element(Security::Open).empty());
}

TEST(Elements, RsnElementSelectsTheCorrectAkmSuite) {
    // Last two bytes of the AKM suite selector identify the authentication method.
    // WPA2-PSK is suite type 2, SAE is 8, 802.1X is 1.
    struct Case { Security sec; std::uint8_t akm; };
    for (const auto& c : {Case{Security::Wpa2Psk, 0x02},
                          Case{Security::Wpa3Sae, 0x08},
                          Case{Security::Wpa2Enterprise, 0x01}}) {
        const Bytes e = FrameBuilder::rsn_element(c.sec);
        ASSERT_FALSE(e.empty());
        EXPECT_EQ(e[0], 48) << "RSN element ID is 48";
        // element header(2) + version(2) + group cipher(4) + pairwise count(2)
        // + pairwise suite(4) + akm count(2) + akm OUI(3) => suite type at 19.
        EXPECT_EQ(e[19], c.akm) << "wrong AKM for " << to_string(c.sec);
    }
}

TEST(Elements, Wpa3RequiresManagementFrameProtection) {
    // WPA3 mandates MFP. Bit 6 = MFP-Required, bit 7 = MFP-Capable.
    const Bytes sae  = FrameBuilder::rsn_element(Security::Wpa3Sae);
    const Bytes psk  = FrameBuilder::rsn_element(Security::Wpa2Psk);
    const std::uint16_t sae_caps = u16le(sae, 20);
    const std::uint16_t psk_caps = u16le(psk, 20);

    EXPECT_EQ(sae_caps & 0x0040, 0x0040) << "WPA3 must set MFP-Required";
    EXPECT_EQ(sae_caps & 0x0080, 0x0080) << "WPA3 must set MFP-Capable";
    EXPECT_EQ(psk_caps & 0x0040, 0x0000) << "WPA2-PSK must not require MFP";
}

TEST(Elements, CapabilityElementsAreCumulativeAcrossPhyGenerations) {
    // A real 802.11ax AP still advertises HT and VHT so older clients can join.
    const Bytes n  = FrameBuilder::phy_capability_elements(Phy::Dot11n);
    const Bytes ac = FrameBuilder::phy_capability_elements(Phy::Dot11ac);
    const Bytes ax = FrameBuilder::phy_capability_elements(Phy::Dot11ax);

    EXPECT_LT(n.size(), ac.size());
    EXPECT_LT(ac.size(), ax.size());
    EXPECT_EQ(n[0], 45) << "802.11n advertises HT Capabilities (45)";
}

TEST(Beacon, CarriesTimestampIntervalAndSsid) {
    const Bytes b = FrameBuilder::beacon(bss(), kSta, 0, 123456);
    ASSERT_GT(b.size(), 36u);
    EXPECT_EQ(u16le(b, 32), 100u) << "beacon interval of 100 TU";
    EXPECT_EQ(u16le(b, 34) & 0x0001, 0x0001) << "ESS capability bit";
    EXPECT_EQ(u16le(b, 34) & 0x0010, 0x0010) << "Privacy bit set for WPA2";
    EXPECT_EQ(b[36], 0) << "first element is the SSID";
}

TEST(Beacon, OpenNetworkClearsThePrivacyBit) {
    const Bytes b = FrameBuilder::beacon(bss(Security::Open), kSta, 0, 0);
    EXPECT_EQ(u16le(b, 34) & 0x0010, 0x0000);
}

TEST(AssocResponse, AidHasTheTopTwoBitsSet) {
    const Bytes f = FrameBuilder::assoc_response(bss(), kSta, StatusCode::Success, 7, 0);
    EXPECT_EQ(u16le(f, 26), static_cast<std::uint16_t>(StatusCode::Success));
    EXPECT_EQ(u16le(f, 28), 0xC007u) << "AID 7 with the two MSBs set by convention";
}

TEST(AssocResponse, StatusCodeIsCarriedVerbatim) {
    const Bytes f = FrameBuilder::assoc_response(bss(), kSta,
                                                 StatusCode::ApUnableToHandleSta, 0, 0);
    EXPECT_EQ(u16le(f, 26), 17u);
}

TEST(Deauth, CarriesTheReasonCode) {
    const Bytes f = FrameBuilder::deauthentication(kSta, kBssid, kBssid,
                                                   ReasonCode::FourWayTimeout, 0);
    EXPECT_EQ((f[0] >> 4) & 0x0F, 12) << "Deauthentication is subtype 12";
    EXPECT_EQ(u16le(f, 24), 15u) << "reason code 15 = 4-way handshake timeout";
}

TEST(Sae, CommitFrameHasGroupScalarAndElement) {
    std::uint8_t scalar[32], element[64];
    std::memset(scalar, 0xA1, sizeof(scalar));
    std::memset(element, 0xB2, sizeof(element));

    const Bytes f = FrameBuilder::sae_commit(kBssid, kSta, scalar, element, 0, false);
    EXPECT_EQ(u16le(f, 24), 3u) << "algorithm 3 = SAE";
    EXPECT_EQ(u16le(f, 26), 1u) << "auth seq 1 = Commit";
    EXPECT_EQ(u16le(f, 28), 0u) << "status Success";
    EXPECT_EQ(u16le(f, 30), 19u) << "finite cyclic group 19 = P-256";
    // 24 header + 2 algo + 2 seq + 2 status + 2 group + 32 scalar + 64 element
    EXPECT_EQ(f.size(), 24u + 8u + 32u + 64u)
        << "an SAE Commit with an empty body is the malformed-frame bug this guards";
}

TEST(Sae, ConfirmFrameHasSendConfirmAndHash) {
    std::uint8_t confirm[32];
    std::memset(confirm, 0xC3, sizeof(confirm));

    const Bytes f = FrameBuilder::sae_confirm(kBssid, kSta, 1, confirm, 0, true);
    EXPECT_EQ(u16le(f, 24), 3u) << "SAE";
    EXPECT_EQ(u16le(f, 26), 2u) << "auth seq 2 = Confirm";
    EXPECT_EQ(u16le(f, 30), 1u) << "send-confirm counter";
    EXPECT_EQ(f.size(), 24u + 8u + 32u);
}

TEST(Eapol, KeyInfoBitsMatchTheSpecForEachMessage) {
    // These bit patterns are how Wireshark decides "Message N of 4", so getting
    // them wrong makes a capture unreadable to every standard tool.
    const auto m1 = eapol::key_info_for(1, Security::Wpa2Psk);
    const auto m2 = eapol::key_info_for(2, Security::Wpa2Psk);
    const auto m3 = eapol::key_info_for(3, Security::Wpa2Psk);
    const auto m4 = eapol::key_info_for(4, Security::Wpa2Psk);

    EXPECT_EQ(m1 & eapol::kKeyMic, 0)                 << "M1 has no MIC (no PTK yet)";
    EXPECT_EQ(m1 & eapol::kKeyAck, eapol::kKeyAck);
    EXPECT_EQ(m2 & eapol::kKeyMic, eapol::kKeyMic)    << "M2 carries the first MIC";
    EXPECT_EQ(m2 & eapol::kSecure, 0);
    EXPECT_EQ(m3 & eapol::kInstall, eapol::kInstall)  << "M3 installs the key";
    EXPECT_EQ(m3 & eapol::kSecure, eapol::kSecure);
    EXPECT_EQ(m3 & eapol::kEncrypted, eapol::kEncrypted) << "M3 carries the encrypted GTK";
    EXPECT_EQ(m4 & eapol::kSecure, eapol::kSecure)    << "M4 is sent secure";
    EXPECT_EQ(m4 & eapol::kInstall, 0);
}

TEST(Eapol, Wpa3UsesTheAesGcmKeyDescriptorVersion) {
    EXPECT_EQ(eapol::key_info_for(1, Security::Wpa3Sae) & 0x0007,
              eapol::kKeyDescVersionAesGcm);
    EXPECT_EQ(eapol::key_info_for(1, Security::Wpa2Psk) & 0x0007,
              eapol::kKeyDescVersionAesHmacSha1);
}

TEST(Eapol, FrameCarriesLlcSnapWithEtherType888E) {
    std::uint8_t nonce[32];
    std::memset(nonce, 0x11, sizeof(nonce));
    const Bytes f = FrameBuilder::eapol_key(1, kSta, kBssid, kBssid, nonce, 1,
                                            Security::Wpa2Psk, 0, false);
    // 24-byte data header, then LLC/SNAP: AA AA 03 00 00 00 88 8E
    EXPECT_EQ(f[24], 0xAA);
    EXPECT_EQ(f[25], 0xAA);
    EXPECT_EQ(f[26], 0x03);
    EXPECT_EQ(u16be(f, 30), 0x888Eu) << "EtherType 0x888E = 802.1X authentication";
    EXPECT_EQ(f[32], 0x02) << "EAPOL version 2";
    EXPECT_EQ(f[33], 0x03) << "packet type 3 = EAPOL-Key";
}

TEST(Eapol, MessageThreeCarriesKeyDataAndMessageFourDoesNot) {
    std::uint8_t nonce[32];
    std::memset(nonce, 0x22, sizeof(nonce));
    const Bytes m3 = FrameBuilder::eapol_key(3, kSta, kBssid, kBssid, nonce, 1,
                                             Security::Wpa2Psk, 0, false);
    const Bytes m4 = FrameBuilder::eapol_key(4, kBssid, kSta, kBssid, nonce, 1,
                                             Security::Wpa2Psk, 0, true);
    EXPECT_GT(m3.size(), m4.size()) << "M3 carries the GTK, M4 carries nothing";
}

TEST(Eapol, MessageFourSendsAZeroNonce) {
    std::uint8_t nonce[32];
    std::memset(nonce, 0xFF, sizeof(nonce));
    const Bytes m4 = FrameBuilder::eapol_key(4, kBssid, kSta, kBssid, nonce, 1,
                                             Security::Wpa2Psk, 0, true);
    // header(24) + snap(8) + eapol hdr(4) + desc type(1) + key info(2)
    // + key len(2) + replay(8) = 49 -> nonce begins at 49.
    for (std::size_t i = 49; i < 49 + 32; ++i)
        EXPECT_EQ(m4[i], 0x00) << "M4 nonce byte " << (i - 49) << " must be zero";
}

TEST(DataFrame, ToDsAndFromDsSwapAddressRoles) {
    const Bytes payload(16, 0x99);
    const Bytes to_ds   = FrameBuilder::data_frame(kSta, kBssid, kBssid, payload, 0, true, false);
    const Bytes from_ds = FrameBuilder::data_frame(kSta, kBssid, kBssid, payload, 0, false, false);
    EXPECT_EQ(to_ds[1] & 0x03, 0x01)   << "ToDS set";
    EXPECT_EQ(from_ds[1] & 0x03, 0x02) << "FromDS set";
    // addr1 differs because the roles swap: BSSID vs destination.
    EXPECT_NE(std::vector<std::uint8_t>(to_ds.begin() + 4, to_ds.begin() + 10),
              std::vector<std::uint8_t>(from_ds.begin() + 4, from_ds.begin() + 10));
}

TEST(DataFrame, EncryptedFrameSetsProtectedBitAndCcmpHeader) {
    const Bytes payload(16, 0x99);
    const Bytes enc = FrameBuilder::data_frame(kSta, kBssid, kBssid, payload, 0, true, true);
    EXPECT_EQ(enc[1] & 0x40, 0x40) << "Protected bit";
    EXPECT_EQ(enc[27] & 0x20, 0x20) << "ExtIV bit in the CCMP header";
}
