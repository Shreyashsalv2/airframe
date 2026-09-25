#include "airframe/state_machine.hpp"

#include <cstring>
#include <cstdio>
#include <sstream>
#include <type_traits>

#include "airframe/json.hpp"

namespace airframe {
namespace {

std::string kv(const std::string& k, const std::string& v) { return k + "=" + v; }
std::string kv(const std::string& k, const char* v) { return k + "=" + v; }

// One template rather than an overload per integer width. Two overloads taking
// `int` and `uint64_t` look harmless but are ambiguous for anything in between
// (uint32_t converts equally well to both), and the compiler is right to refuse.
template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
std::string kv(const std::string& k, T v) { return k + "=" + std::to_string(v); }

std::string join(const std::vector<std::string>& parts) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) out += " ";
        out += parts[i];
    }
    return out;
}

// Typical per-stage durations in milliseconds, drawn from real-world behaviour.
// A 5 GHz association usually completes in 150-400ms end to end; DHCP dominates.
constexpr std::uint32_t kScanMs    = 1200;   // full passive+active scan
constexpr std::uint32_t kAuthMs    = 18;
constexpr std::uint32_t kAssocMs   = 22;
constexpr std::uint32_t kFourWayMs = 55;
constexpr std::uint32_t kDhcpMs    = 340;
constexpr std::uint32_t kRoamMs    = 95;

// Timeouts a real supplicant applies before giving up on a stage.
constexpr std::uint32_t kAuthTimeoutMs    = 3000;
constexpr std::uint32_t kFourWayTimeoutMs = 2000;
constexpr std::uint32_t kDhcpTimeoutMs    = 8000;

}  // namespace

// ---------------------------------------------------------------- table

const std::map<std::pair<State, Event>, State>& StateMachine::table() {
    // Built once, on first use. Static-local initialisation is thread-safe in
    // C++11 and later, which is why this is a function rather than a global.
    static const std::map<std::pair<State, Event>, State> t = [] {
        std::map<std::pair<State, Event>, State> m;
        auto add = [&m](State from, Event ev, State to) { m[{from, ev}] = to; };

        // Discovery
        add(State::Idle,           Event::ScanStart,     State::Scanning);
        add(State::Scanning,       Event::ScanDone,      State::Idle);
        add(State::Scanning,       Event::AuthStart,     State::Authenticating);
        add(State::Idle,           Event::AuthStart,     State::Authenticating);

        // Authentication
        add(State::Authenticating, Event::AuthOk,        State::Associating);
        add(State::Authenticating, Event::AuthFail,      State::Failed);
        add(State::Authenticating, Event::Deauth,        State::Disconnecting);

        // Association. Two successors on AssocOk is not possible in a map, so the
        // driver picks the event: secured networks send FourWayStart, open
        // networks send DhcpStart. Keeping the choice in the driver keeps this
        // table a pure function of (state, event) with no hidden config input.
        add(State::Associating,    Event::AssocOk,       State::Associating);
        add(State::Associating,    Event::AssocFail,     State::Failed);
        add(State::Associating,    Event::FourWayStart,  State::FourWay);
        add(State::Associating,    Event::DhcpStart,     State::Dhcp);
        add(State::Associating,    Event::Deauth,        State::Disconnecting);

        // 4-way handshake
        add(State::FourWay,        Event::FourWayOk,     State::FourWay);
        add(State::FourWay,        Event::DhcpStart,     State::Dhcp);
        add(State::FourWay,        Event::FourWayFail,   State::Failed);
        add(State::FourWay,        Event::Deauth,        State::Disconnecting);

        // Address acquisition
        add(State::Dhcp,           Event::DhcpOk,        State::Dhcp);
        add(State::Dhcp,           Event::LinkUp,        State::Connected);
        add(State::Dhcp,           Event::DhcpFail,      State::Failed);
        add(State::Dhcp,           Event::Deauth,        State::Disconnecting);

        // Steady state
        add(State::Connected,      Event::LinkUp,        State::Connected);
        add(State::Connected,      Event::RoamStart,     State::Roaming);
        add(State::Connected,      Event::Deauth,        State::Disconnecting);
        add(State::Connected,      Event::DisconnectReq, State::Disconnecting);

        // Roaming
        add(State::Roaming,        Event::RoamOk,        State::Connected);
        add(State::Roaming,        Event::RoamFail,      State::Failed);
        add(State::Roaming,        Event::Deauth,        State::Disconnecting);

        // Teardown
        add(State::Disconnecting,  Event::Disconnected,  State::Idle);
        add(State::Failed,         Event::DisconnectReq, State::Idle);

        // Reset is legal from anywhere — it is the "put the radio back" escape hatch.
        for (int i = 0; i <= static_cast<int>(State::Failed); ++i)
            add(static_cast<State>(i), Event::Reset, State::Idle);

        return m;
    }();
    return t;
}

bool StateMachine::is_legal(State from, Event ev) noexcept {
    return table().find({from, ev}) != table().end();
}

State StateMachine::next_state(State from, Event ev) {
    const auto it = table().find({from, ev});
    if (it == table().end()) throw IllegalTransition(from, ev);
    return it->second;
}

// ---------------------------------------------------------------- lifecycle

StateMachine::StateMachine(SimConfig config)
    : config_(std::move(config)), rng_(config_.seed) {
    logger_.open(config_.log_path, config_.log_stderr);
    if (!config_.pcap_path.empty()) pcap_.open(config_.pcap_path);

    rng_.fill_mac(sta_);
    rng_.fill_mac(bssid_);
    rng_.fill_mac(bssid_alt_);
    build_bss();
    rssi_dbm_ = bss_.rssi_dbm;

    log(LogLevel::Notice, "wifid",
        join({"sim start",
              kv("ssid", config_.ssid),
              kv("security", to_string(config_.security)),
              kv("band", to_string(config_.band)),
              kv("channel", static_cast<int>(config_.channel)),
              kv("width", static_cast<int>(config_.width)),
              kv("phy", to_string(config_.phy)),
              kv("seed", config_.seed),
              kv("fault", to_string(config_.fault.fault)),
              kv("sta", mac_to_string(sta_))}));
}

StateMachine::~StateMachine() {
    pcap_.close();
    logger_.close();
}

void StateMachine::build_bss() {
    bss_.ssid     = config_.ssid;
    std::memcpy(bss_.bssid, bssid_, 6);
    bss_.band     = config_.band;
    bss_.channel  = config_.channel;
    bss_.width    = config_.width;
    bss_.phy      = config_.phy;
    bss_.security = config_.security;
    bss_.rssi_dbm = -45;
    bss_.noise_dbm = -95;
}

void StateMachine::log(LogLevel level, const std::string& component, const std::string& message) {
    logger_.log(clock_.now_ms(), clock_.timestamp(), level, component, message);
}

RadioInfo StateMachine::radio_now(bool bad_fcs) const {
    RadioInfo r;
    r.freq_mhz = channel_to_freq(config_.band, config_.channel);
    if (r.freq_mhz == 0) r.freq_mhz = 5180;
    r.is_5ghz  = (config_.band != Band::Band2_4GHz);
    r.rssi_dbm = static_cast<std::int8_t>(rssi_dbm_);
    r.rate_500kbps = (config_.band == Band::Band2_4GHz) ? 22 : 12;
    r.bad_fcs = bad_fcs;
    return r;
}

void StateMachine::emit(const Bytes& frame, bool from_ap, bool bad_fcs) {
    if (from_ap) ++rx_frames_; else ++tx_frames_;
    pcap_.write_frame(clock_.now_ms(), frame, radio_now(bad_fcs));
}

void StateMachine::transition(Event ev, const std::string& why) {
    const State from = state_;
    const State to   = next_state(from, ev);   // throws if illegal
    state_ = to;

    transition_history_.push_back(std::string(to_string(from)) + "--" + to_string(ev) + "->" +
                                  to_string(to));
    std::vector<std::string> parts{"state transition", kv("from", to_string(from)),
                                   kv("event", to_string(ev)), kv("to", to_string(to))};
    if (!why.empty()) parts.push_back(kv("reason", why));
    log(LogLevel::Debug, "wifid", join(parts));
}

bool StateMachine::fault_fires(Fault f) noexcept {
    if (config_.fault.fault != f) return false;
    // probability == 1.0 means deterministic. Below that we are in flake mode and
    // the seeded RNG decides — reproducibly, which is the entire point.
    if (config_.fault.probability >= 1.0) return true;
    return rng_.bernoulli(config_.fault.probability);
}

void StateMachine::reset() {
    if (state_ != State::Idle) transition(Event::Reset, "explicit reset");
    tx_frames_ = rx_frames_ = tx_retries_ = 0;
    ip_address_.clear();
    rssi_dbm_ = bss_.rssi_dbm;
    seq_ = 0;
    replay_counter_ = 1;
}

// ---------------------------------------------------------------- scan

std::vector<ScanEntry> StateMachine::scan() {
    std::vector<ScanEntry> out;

    // A station scanning while already associated is a BACKGROUND (off-channel)
    // scan, and it is how roaming works in practice: the radio briefly leaves the
    // operating channel, samples neighbours, and returns -- without ever leaving
    // the association. So the association state must NOT change here.
    //
    // Modelling this as IDLE->SCANNING would be wrong in a way that matters: it
    // would imply the link dropped, and any test asserting "still connected after
    // a scan" would fail against a DUT that is behaving correctly.
    const bool background = (state_ == State::Connected);
    if (background) {
        log(LogLevel::Info, "wifid",
            join({"background scan", kv("band", to_string(config_.band)),
                  kv("type", "off-channel"), kv("assoc_retained", 1)}));
    } else {
        transition(Event::ScanStart);
    }
    log(LogLevel::Info, "wifid", join({"scan request", kv("band", to_string(config_.band)),
                                       kv("type", "active")}));

    // Probe request from the station, then the AP's reply plus a beacon.
    emit(FrameBuilder::probe_request(sta_, config_.ssid, seq_++), /*from_ap=*/false);
    advance(rng_.stage_ms(40));

    if (fault_fires(Fault::ScanEmpty)) {
        advance(rng_.stage_ms(kScanMs));
        log(LogLevel::Warn, "wifid", join({"scan complete", kv("networks", 0),
                                           kv("fault", to_string(Fault::ScanEmpty))}));
        if (!background) transition(Event::ScanDone, "no networks found");
        return out;
    }

    emit(FrameBuilder::probe_response(bss_, sta_, seq_++, clock_.now_ms() * 1000), true);
    advance(rng_.stage_ms(60));
    emit(FrameBuilder::beacon(bss_, sta_, seq_++, clock_.now_ms() * 1000), true);

    ScanEntry primary;
    primary.ssid     = config_.ssid;
    primary.bssid    = mac_to_string(bssid_);
    primary.band     = config_.band;
    primary.channel  = config_.channel;
    primary.width    = config_.width;
    primary.phy      = config_.phy;
    primary.security = config_.security;
    primary.rssi_dbm = rssi_dbm_ + rng_.uniform_int(-3, 3);
    out.push_back(primary);

    // A second BSS advertising the same SSID — this is what makes roaming
    // meaningful, and it is what a real enterprise deployment looks like.
    ScanEntry secondary = primary;
    secondary.bssid    = mac_to_string(bssid_alt_);
    secondary.rssi_dbm = primary.rssi_dbm - rng_.uniform_int(8, 20);
    secondary.channel  = static_cast<std::uint8_t>(
        config_.band == Band::Band2_4GHz ? 11 : 149);
    out.push_back(secondary);

    advance(rng_.stage_ms(kScanMs));
    for (const auto& e : out)
        log(LogLevel::Info, "wifid",
            join({"scan result", kv("ssid", e.ssid), kv("bssid", e.bssid),
                  kv("rssi", e.rssi_dbm), kv("channel", static_cast<int>(e.channel)),
                  kv("security", to_string(e.security))}));
    log(LogLevel::Info, "wifid",
        join({"scan complete", kv("networks", static_cast<std::uint64_t>(out.size()))}));

    if (!background) transition(Event::ScanDone);
    return out;
}

// ---------------------------------------------------------------- connect

ConnectResult StateMachine::connect() {
    ConnectResult res;
    res.bssid = mac_to_string(bssid_);
    const std::uint64_t t_start = clock_.now_ms();

    // ---- interop pre-check -------------------------------------------------
    // Invalid band/security or band/PHY combinations are refused before any
    // frames go out, exactly as a real supplicant would refuse them. This is
    // what turns the interop matrix into a meaningful test rather than noise.
    if (!security_supported_on_band(config_.security, config_.band)) {
        res.ok        = false;
        res.final_state = State::Failed;
        res.failed_at = State::Idle;
        res.status    = StatusCode::InvalidAkmp;
        res.message   = std::string("security ") + to_string(config_.security) +
                        " is not permitted on " + to_string(config_.band);
        log(LogLevel::Error, "wifid", join({"association refused", kv("reason", res.message)}));
        state_ = State::Failed;
        last_result_ = res;
        return res;
    }
    if (!phy_supports_width(config_.phy, config_.width)) {
        res.ok        = false;
        res.final_state = State::Failed;
        res.failed_at = State::Idle;
        res.status    = StatusCode::CapabilitiesMismatch;
        res.message   = std::string("PHY ") + to_string(config_.phy) + " supports at most " +
                        std::to_string(max_width_for_phy(config_.phy)) + "MHz, requested " +
                        std::to_string(config_.width) + "MHz";
        log(LogLevel::Error, "wifid", join({"association refused", kv("reason", res.message)}));
        state_ = State::Failed;
        last_result_ = res;
        return res;
    }
    if (!phy_supported_on_band(config_.phy, config_.band)) {
        res.ok        = false;
        res.final_state = State::Failed;
        res.failed_at = State::Idle;
        res.status    = StatusCode::CapabilitiesMismatch;
        res.message   = std::string("PHY ") + to_string(config_.phy) +
                        " does not operate on " + to_string(config_.band);
        log(LogLevel::Error, "wifid", join({"association refused", kv("reason", res.message)}));
        state_ = State::Failed;
        last_result_ = res;
        return res;
    }

    // ---- scan --------------------------------------------------------------
    const std::uint64_t scan_start = clock_.now_ms();
    if (state_ == State::Idle) {
        const auto found = scan();
        res.timings.scan_ms = clock_.now_ms() - scan_start;
        if (found.empty()) {
            res.ok        = false;
            res.fault     = Fault::ScanEmpty;
            res.failed_at = State::Scanning;
            res.final_state = State::Failed;
            res.message   = fault_description(Fault::ScanEmpty);
            state_ = State::Failed;
            res.timings.total_ms = clock_.now_ms() - t_start;
            last_result_ = res;
            return res;
        }
    }

    // ---- channel contention ------------------------------------------------
    // CHANNEL_BUSY does not fail the connection outright; it degrades it. That
    // asymmetry matters: not every fault is a hard failure, and a test suite that
    // only understands pass/fail cannot express "worked, but badly".
    const bool busy = fault_fires(Fault::ChannelBusy);
    if (busy) {
        log(LogLevel::Warn, "driver",
            join({"channel congestion detected", kv("channel", static_cast<int>(config_.channel)),
                  kv("cca_busy_pct", rng_.uniform_int(62, 91))}));
    }
    const std::uint32_t slow = busy ? 3 : 1;

    // ---- LOW_RSSI ----------------------------------------------------------
    if (fault_fires(Fault::LowRssi)) {
        rssi_dbm_ = rng_.uniform_int(-92, -84);
        log(LogLevel::Warn, "driver",
            join({"signal below usable threshold", kv("rssi", rssi_dbm_),
                  kv("threshold", -82)}));
    }

    // ---- authentication ----------------------------------------------------
    transition(Event::AuthStart);
    const std::uint64_t auth_start = clock_.now_ms();
    const bool sae = (config_.security == Security::Wpa3Sae);

    if (sae) {
        // WPA3: SAE Commit from the station. Scalar and element are random bytes
        // here rather than genuine P-256 values -- structurally valid, not
        // cryptographically valid, which is documented and deliberate.
        std::uint8_t scalar[32], element[64];
        rng_.fill_bytes(scalar, 32);
        rng_.fill_bytes(element, 64);
        log(LogLevel::Info, "supplicant",
            join({"SAE commit", kv("dir", "STA->AP"), kv("group", 19),
                  kv("bssid", res.bssid)}));
        emit(FrameBuilder::sae_commit(bssid_, sta_, scalar, element, seq_++, false), false);
        advance(rng_.stage_ms(kAuthMs / 2 * slow));
    } else {
        log(LogLevel::Info, "wifid",
            join({"auth request", kv("bssid", res.bssid), kv("algo", "OPEN"), kv("seq", 1)}));
        emit(FrameBuilder::authentication(bssid_, sta_, 0, 1, StatusCode::Success,
                                          seq_++, false), false);
        advance(rng_.stage_ms(kAuthMs * slow));
    }

    if (fault_fires(Fault::AuthTimeout)) {
        advance(kAuthTimeoutMs);
        res.timings.auth_ms = clock_.now_ms() - auth_start;
        log(LogLevel::Error, "wifid",
            join({"auth timeout", kv("bssid", res.bssid), kv("timeout_ms", kAuthTimeoutMs),
                  kv("status", to_string(StatusCode::AuthTimeout))}));
        transition(Event::AuthFail, "no response from AP");
        res.ok = false;
        res.fault = Fault::AuthTimeout;
        res.status = StatusCode::AuthTimeout;
        res.failed_at = State::Authenticating;
        res.final_state = State::Failed;
        res.message = fault_description(Fault::AuthTimeout);
        res.timings.total_ms = clock_.now_ms() - t_start;
        last_result_ = res;
        return res;
    }

    if (sae) {
        // AP replies with its own Commit, then both sides exchange Confirm.
        std::uint8_t ap_scalar[32], ap_element[64], confirm[32];
        rng_.fill_bytes(ap_scalar, 32);
        rng_.fill_bytes(ap_element, 64);
        rng_.fill_bytes(confirm, 32);
        emit(FrameBuilder::sae_commit(bssid_, sta_, ap_scalar, ap_element, seq_++, true), true);
        advance(rng_.stage_ms(kAuthMs / 2 * slow));
        log(LogLevel::Info, "supplicant", join({"SAE commit", kv("dir", "AP->STA"),
                                               kv("group", 19)}));

        emit(FrameBuilder::sae_confirm(bssid_, sta_, 1, confirm, seq_++, false), false);
        advance(rng_.stage_ms(kAuthMs / 2 * slow));
        log(LogLevel::Info, "supplicant", join({"SAE confirm", kv("dir", "STA->AP"),
                                               kv("send_confirm", 1)}));

        emit(FrameBuilder::sae_confirm(bssid_, sta_, 1, confirm, seq_++, true), true);
        log(LogLevel::Notice, "supplicant",
            join({"SAE authentication complete", kv("group", 19), kv("pmk", "derived")}));
    } else {
        emit(FrameBuilder::authentication(bssid_, sta_, 0, 2, StatusCode::Success,
                                          seq_++, true), true);
    }
    res.timings.auth_ms = clock_.now_ms() - auth_start;
    log(LogLevel::Info, "wifid",
        join({"auth response", kv("bssid", res.bssid), kv("status", 0),
              kv("elapsed_ms", res.timings.auth_ms)}));
    transition(Event::AuthOk);

    // ---- association -------------------------------------------------------
    const std::uint64_t assoc_start = clock_.now_ms();
    log(LogLevel::Info, "wifid", join({"assoc request", kv("bssid", res.bssid),
                                       kv("ssid", config_.ssid)}));
    emit(FrameBuilder::assoc_request(bss_, sta_, seq_++), false);
    advance(rng_.stage_ms(kAssocMs * slow));

    if (fault_fires(Fault::AssocReject)) {
        const StatusCode sc = config_.fault.code
                                  ? static_cast<StatusCode>(config_.fault.code)
                                  : fault_status_code(Fault::AssocReject);
        emit(FrameBuilder::assoc_response(bss_, sta_, sc, 0, seq_++), true);
        res.timings.assoc_ms = clock_.now_ms() - assoc_start;
        log(LogLevel::Error, "wifid",
            join({"assoc rejected", kv("bssid", res.bssid),
                  kv("status", static_cast<int>(sc)), kv("status_name", to_string(sc))}));
        transition(Event::AssocFail, to_string(sc));
        res.ok = false;
        res.fault = Fault::AssocReject;
        res.status = sc;
        res.failed_at = State::Associating;
        res.final_state = State::Failed;
        res.message = fault_description(Fault::AssocReject);
        res.timings.total_ms = clock_.now_ms() - t_start;
        last_result_ = res;
        return res;
    }

    const std::uint16_t aid = static_cast<std::uint16_t>(rng_.uniform_int(1, 32));
    emit(FrameBuilder::assoc_response(bss_, sta_, StatusCode::Success, aid, seq_++), true);
    res.timings.assoc_ms = clock_.now_ms() - assoc_start;
    log(LogLevel::Notice, "wifid",
        join({"assoc resp", kv("status", 0), kv("aid", static_cast<int>(aid)),
              kv("bssid", res.bssid), kv("elapsed_ms", res.timings.assoc_ms)}));
    transition(Event::AssocOk);

    // ---- 4-way handshake (skipped on open networks) ------------------------
    if (config_.security != Security::Open) {
        transition(Event::FourWayStart);
        const std::uint64_t fw_start = clock_.now_ms();
        std::uint8_t anonce[32], snonce[32];
        rng_.fill_bytes(anonce, 32);
        rng_.fill_bytes(snonce, 32);

        // M1: AP -> STA, carries ANonce
        log(LogLevel::Info, "supplicant", join({"EAPOL-Key M1", kv("dir", "AP->STA"),
                                                kv("replay", replay_counter_)}));
        emit(FrameBuilder::eapol_key(1, sta_, bssid_, bssid_, anonce, replay_counter_,
                                     config_.security, seq_++, false), true);
        advance(rng_.stage_ms(kFourWayMs / 4 * slow));

        // M2: STA -> AP, carries SNonce + MIC
        log(LogLevel::Info, "supplicant", join({"EAPOL-Key M2", kv("dir", "STA->AP"),
                                                kv("replay", replay_counter_)}));
        emit(FrameBuilder::eapol_key(2, bssid_, sta_, bssid_, snonce, replay_counter_,
                                     config_.security, seq_++, true), false);
        advance(rng_.stage_ms(kFourWayMs / 4 * slow));

        // PMK_MISMATCH: the AP receives M2 and its MIC check fails, so it never
        // sends M3 and deauthenticates with an 802.1X failure reason.
        if (fault_fires(Fault::PmkMismatch)) {
            res.timings.fourway_ms = clock_.now_ms() - fw_start;
            log(LogLevel::Error, "supplicant",
                join({"EAPOL-Key MIC verification failed", kv("msg", 2),
                      kv("reason", "PMK mismatch"), kv("hint", "wrong passphrase")}));
            emit(FrameBuilder::deauthentication(sta_, bssid_, bssid_,
                                                ReasonCode::Ieee8021xFailed, seq_++), true);
            log(LogLevel::Error, "wifid",
                join({"deauth received", kv("reason", static_cast<int>(ReasonCode::Ieee8021xFailed)),
                      kv("reason_name", to_string(ReasonCode::Ieee8021xFailed))}));
            transition(Event::FourWayFail, "PMK mismatch");
            res.ok = false;
            res.fault = Fault::PmkMismatch;
            res.reason = ReasonCode::Ieee8021xFailed;
            res.status = StatusCode::InvalidPmkid;
            res.failed_at = State::FourWay;
            res.final_state = State::Failed;
            res.message = fault_description(Fault::PmkMismatch);
            res.timings.total_ms = clock_.now_ms() - t_start;
            last_result_ = res;
            return res;
        }

        // FOURWAY_M3_TIMEOUT: M3 simply never arrives. The supplicant retries
        // M2 a few times (real supplicants retry 3-4 times) and then gives up.
        if (fault_fires(Fault::FourWayM3Timeout)) {
            for (int retry = 1; retry <= 3; ++retry) {
                advance(kFourWayTimeoutMs / 4);
                ++tx_retries_;
                log(LogLevel::Warn, "supplicant",
                    join({"EAPOL-Key M3 not received, retransmitting M2",
                          kv("attempt", retry), kv("timeout_ms", kFourWayTimeoutMs / 4)}));
                emit(FrameBuilder::eapol_key(2, bssid_, sta_, bssid_, snonce,
                                             replay_counter_, config_.security, seq_++, true),
                     false);
            }
            advance(kFourWayTimeoutMs / 4);
            res.timings.fourway_ms = clock_.now_ms() - fw_start;
            log(LogLevel::Error, "supplicant",
                join({"4-way handshake timeout", kv("last_msg_received", 1),
                      kv("expected", 3), kv("elapsed_ms", res.timings.fourway_ms)}));
            emit(FrameBuilder::deauthentication(sta_, bssid_, bssid_,
                                                ReasonCode::FourWayTimeout, seq_++), true);
            log(LogLevel::Error, "wifid",
                join({"deauth received", kv("reason", static_cast<int>(ReasonCode::FourWayTimeout)),
                      kv("reason_name", to_string(ReasonCode::FourWayTimeout))}));
            transition(Event::FourWayFail, "M3 timeout");
            res.ok = false;
            res.fault = Fault::FourWayM3Timeout;
            res.reason = ReasonCode::FourWayTimeout;
            res.failed_at = State::FourWay;
            res.final_state = State::Failed;
            res.message = fault_description(Fault::FourWayM3Timeout);
            res.timings.total_ms = clock_.now_ms() - t_start;
            last_result_ = res;
            return res;
        }

        // M3: AP -> STA, carries GTK + install
        log(LogLevel::Info, "supplicant", join({"EAPOL-Key M3", kv("dir", "AP->STA"),
                                                kv("install", 1)}));
        emit(FrameBuilder::eapol_key(3, sta_, bssid_, bssid_, anonce, replay_counter_,
                                     config_.security, seq_++, false), true);
        advance(rng_.stage_ms(kFourWayMs / 4 * slow));

        // M4: STA -> AP, acknowledgement
        log(LogLevel::Info, "supplicant", join({"EAPOL-Key M4", kv("dir", "STA->AP")}));
        emit(FrameBuilder::eapol_key(4, bssid_, sta_, bssid_, snonce, replay_counter_,
                                     config_.security, seq_++, true), false);
        advance(rng_.stage_ms(kFourWayMs / 4 * slow));
        ++replay_counter_;

        res.timings.fourway_ms = clock_.now_ms() - fw_start;
        log(LogLevel::Notice, "supplicant",
            join({"4-way handshake complete", kv("cipher", "CCMP-128"),
                  kv("akm", to_string(config_.security)),
                  kv("elapsed_ms", res.timings.fourway_ms)}));
        transition(Event::FourWayOk);
        transition(Event::DhcpStart);
    } else {
        log(LogLevel::Info, "wifid", "open network, skipping 4-way handshake");
        transition(Event::DhcpStart);
    }

    // ---- DHCP --------------------------------------------------------------
    const std::uint64_t dhcp_start = clock_.now_ms();
    log(LogLevel::Info, "dhcp", join({"DHCPDISCOVER", kv("iface", "en0")}));
    advance(rng_.stage_ms(kDhcpMs / 3 * slow));
    log(LogLevel::Info, "dhcp", join({"DHCPOFFER", kv("server", "192.168.1.1")}));
    advance(rng_.stage_ms(kDhcpMs / 3 * slow));
    log(LogLevel::Info, "dhcp", join({"DHCPREQUEST", kv("server", "192.168.1.1")}));

    if (fault_fires(Fault::DhcpNak)) {
        advance(kDhcpTimeoutMs);
        res.timings.dhcp_ms = clock_.now_ms() - dhcp_start;
        log(LogLevel::Error, "dhcp",
            join({"DHCPNAK", kv("server", "192.168.1.1"),
                  kv("reason", "requested address not available"),
                  kv("elapsed_ms", res.timings.dhcp_ms)}));
        log(LogLevel::Error, "wifid",
            join({"link up but no IPv4 address", kv("state", "DHCP_FAILED")}));
        transition(Event::DhcpFail, "DHCPNAK");
        res.ok = false;
        res.fault = Fault::DhcpNak;
        res.failed_at = State::Dhcp;
        res.final_state = State::Failed;
        res.message = fault_description(Fault::DhcpNak);
        res.timings.total_ms = clock_.now_ms() - t_start;
        last_result_ = res;
        return res;
    }

    advance(rng_.stage_ms(kDhcpMs / 3 * slow));
    char ipbuf[32];
    std::snprintf(ipbuf, sizeof(ipbuf), "192.168.1.%d", rng_.uniform_int(20, 200));
    ip_address_ = ipbuf;
    res.timings.dhcp_ms = clock_.now_ms() - dhcp_start;
    log(LogLevel::Notice, "dhcp",
        join({"DHCPACK", kv("ip", ip_address_), kv("lease_s", 86400),
              kv("elapsed_ms", res.timings.dhcp_ms)}));
    transition(Event::DhcpOk);
    transition(Event::LinkUp);

    res.timings.total_ms = clock_.now_ms() - t_start;
    res.ok          = true;
    res.final_state = State::Connected;
    res.status      = StatusCode::Success;
    res.ip_address  = ip_address_;
    res.fault       = busy ? Fault::ChannelBusy : Fault::None;
    res.message     = busy ? "connected, but channel congestion degraded the link"
                           : "connected";

    log(LogLevel::Notice, "wifid",
        join({"link up", kv("ssid", config_.ssid), kv("bssid", res.bssid),
              kv("ip", ip_address_), kv("rssi", rssi_dbm_),
              kv("channel", static_cast<int>(config_.channel)),
              kv("width", static_cast<int>(config_.width)),
              kv("phy", to_string(config_.phy)),
              kv("total_ms", res.timings.total_ms)}));

    last_result_ = res;
    return res;
}

// ---------------------------------------------------------------- roam

ConnectResult StateMachine::roam() {
    ConnectResult res = last_result_;
    res.timings = StageTimings{};
    const std::uint64_t t0 = clock_.now_ms();

    if (state_ != State::Connected) {
        res.ok = false;
        res.message = "roam requires CONNECTED state";
        res.final_state = state_;
        return res;
    }

    transition(Event::RoamStart);
    const std::string from_bssid = mac_to_string(bssid_);
    log(LogLevel::Info, "wifid",
        join({"roam start", kv("from_bssid", from_bssid),
              kv("to_bssid", mac_to_string(bssid_alt_)), kv("trigger", "rssi_threshold")}));

    // ROAM_PINGPONG: the station bounces between the two BSSes several times
    // before settling. Each bounce is a real disruption to user traffic, which is
    // why this is treated as a failure even though the link ends up "connected".
    if (fault_fires(Fault::RoamPingpong)) {
        for (int i = 0; i < 4; ++i) {
            std::uint8_t* target = (i % 2 == 0) ? bssid_alt_ : bssid_;
            advance(rng_.stage_ms(kRoamMs));
            emit(FrameBuilder::authentication(target, sta_, 0, 1, StatusCode::Success,
                                              seq_++, false), false);
            emit(FrameBuilder::assoc_request(bss_, sta_, seq_++), false);
            log(LogLevel::Warn, "wifid",
                join({"roam", kv("iteration", i + 1), kv("bssid", mac_to_string(target)),
                      kv("rssi", rng_.uniform_int(-74, -66))}));
        }
        res.timings.total_ms = clock_.now_ms() - t0;
        log(LogLevel::Error, "wifid",
            join({"roam instability detected", kv("transitions", 4),
                  kv("window_ms", res.timings.total_ms),
                  kv("reason", "ping-pong between BSSIDs")}));
        transition(Event::RoamFail, "ping-pong");
        res.ok = false;
        res.fault = Fault::RoamPingpong;
        res.failed_at = State::Roaming;
        res.final_state = State::Failed;
        res.message = fault_description(Fault::RoamPingpong);
        last_result_ = res;
        return res;
    }

    std::memcpy(bssid_, bssid_alt_, 6);
    build_bss();
    advance(rng_.stage_ms(kRoamMs));
    emit(FrameBuilder::authentication(bssid_, sta_, 0, 1, StatusCode::Success, seq_++, false),
         false);
    emit(FrameBuilder::assoc_request(bss_, sta_, seq_++), false);
    emit(FrameBuilder::assoc_response(bss_, sta_, StatusCode::Success, 7, seq_++), true);
    advance(rng_.stage_ms(kRoamMs / 2));

    res.timings.total_ms = clock_.now_ms() - t0;
    res.bssid = mac_to_string(bssid_);
    res.ok = true;
    res.final_state = State::Connected;
    res.message = "roam complete";
    log(LogLevel::Notice, "wifid",
        join({"roam complete", kv("from_bssid", from_bssid), kv("to_bssid", res.bssid),
              kv("elapsed_ms", res.timings.total_ms)}));
    transition(Event::RoamOk);
    last_result_ = res;
    return res;
}

// ---------------------------------------------------------------- connected

bool StateMachine::run_connected(std::uint64_t ms) {
    if (state_ != State::Connected) return false;

    const std::uint64_t deadline = clock_.now_ms() + ms;
    const bool busy = (config_.fault.fault == Fault::ChannelBusy);

    while (clock_.now_ms() < deadline) {
        advance(100);

        // Ordinary traffic, plus retries. A healthy link retries ~2% of frames;
        // a congested one can exceed 30%, which is the signal the pcap analysis
        // layer keys on.
        const int frames = rng_.uniform_int(8, 24);
        for (int i = 0; i < frames; ++i) {
            const bool will_retry = rng_.bernoulli(busy ? 0.34 : 0.02);
            const bool encrypted  = (config_.security != Security::Open);
            Bytes payload(static_cast<std::size_t>(rng_.uniform_int(48, 300)), 0x5A);
            const std::uint16_t seq = seq_++;

            // Original transmission.
            emit(FrameBuilder::data_frame(bssid_, sta_, bssid_, payload, seq, true,
                                          encrypted, /*retry=*/false), false);

            // A retransmission is a SECOND frame on the air carrying the same
            // sequence number with the Retry bit set. Modelling it as a flag on the
            // original frame (the first version of this code) left the internal
            // retry counter disagreeing with the capture: stats said 34%, the pcap
            // said 0%. See BUILD_JOURNAL.md #13.
            if (will_retry) {
                ++tx_retries_;
                emit(FrameBuilder::data_frame(bssid_, sta_, bssid_, payload, seq, true,
                                              encrypted, /*retry=*/true),
                     false, rng_.bernoulli(0.1));
            }
        }

        // RSSI random walk, so signal traces look like real measurements.
        rssi_dbm_ += rng_.uniform_int(-2, 2);
        if (rssi_dbm_ > -30) rssi_dbm_ = -30;
        if (rssi_dbm_ < -95) rssi_dbm_ = -95;

        if (fault_fires(Fault::BeaconLoss)) {
            log(LogLevel::Warn, "driver",
                join({"beacon miss", kv("consecutive", 7), kv("bssid", mac_to_string(bssid_))}));
            advance(2000);
            log(LogLevel::Error, "wifid",
                join({"connection lost", kv("reason", static_cast<int>(ReasonCode::BeaconLoss)),
                      kv("reason_name", to_string(ReasonCode::BeaconLoss)),
                      kv("last_rssi", rssi_dbm_)}));
            emit(FrameBuilder::deauthentication(sta_, bssid_, bssid_, ReasonCode::BeaconLoss,
                                                seq_++), true);
            transition(Event::Deauth, "beacon loss");
            transition(Event::Disconnected);
            return false;
        }

        if (fault_fires(Fault::Deauth)) {
            const ReasonCode rc = config_.fault.code
                                      ? static_cast<ReasonCode>(config_.fault.code)
                                      : fault_reason_code(Fault::Deauth);
            emit(FrameBuilder::deauthentication(sta_, bssid_, bssid_, rc, seq_++), true);
            log(LogLevel::Error, "wifid",
                join({"deauth received", kv("reason", static_cast<int>(rc)),
                      kv("reason_name", to_string(rc)), kv("bssid", mac_to_string(bssid_))}));
            transition(Event::Deauth, to_string(rc));
            transition(Event::Disconnected);
            return false;
        }
    }
    return true;
}

void StateMachine::disconnect(ReasonCode reason) {
    if (state_ == State::Idle) return;
    if (state_ != State::Disconnecting) {
        if (is_legal(state_, Event::DisconnectReq)) {
            transition(Event::DisconnectReq, to_string(reason));
        } else {
            transition(Event::Reset, "forced disconnect from non-connected state");
            return;
        }
    }
    emit(FrameBuilder::deauthentication(bssid_, sta_, bssid_, reason, seq_++), false);
    log(LogLevel::Notice, "wifid",
        join({"disconnect", kv("reason", static_cast<int>(reason)),
              kv("reason_name", to_string(reason))}));
    advance(12);
    transition(Event::Disconnected);
    ip_address_.clear();
}

// ---------------------------------------------------------------- stats

LinkStats StateMachine::stats() const {
    LinkStats s;
    s.rssi_dbm  = rssi_dbm_;
    s.noise_dbm = bss_.noise_dbm;
    s.snr_db    = rssi_dbm_ - bss_.noise_dbm;
    s.channel   = config_.channel;
    s.width_mhz = config_.width;
    s.tx_frames = tx_frames_;
    s.rx_frames = rx_frames_;
    s.tx_retries = tx_retries_;
    s.retry_rate = tx_frames_ ? static_cast<double>(tx_retries_) / static_cast<double>(tx_frames_)
                              : 0.0;

    // A crude but directionally correct PHY rate model: base rate per PHY
    // generation, scaled by channel width, then derated by SNR. Real rate
    // selection is far more complex, but this reproduces the property that
    // matters for testing — rate falls as signal degrades.
    std::uint32_t base = 0;
    switch (config_.phy) {
        case Phy::Dot11n:  base = 72;  break;
        case Phy::Dot11ac: base = 433; break;
        case Phy::Dot11ax: base = 600; break;
        case Phy::Dot11be: base = 1200; break;
    }
    double width_factor = 1.0;
    switch (config_.width) {
        case 20:  width_factor = 0.5;  break;
        case 40:  width_factor = 1.0;  break;
        case 80:  width_factor = 2.1;  break;
        case 160: width_factor = 4.2;  break;
        case 320: width_factor = 8.4;  break;
        default:  width_factor = 1.0;  break;
    }
    double snr_factor = 1.0;
    if (s.snr_db < 15)      snr_factor = 0.15;
    else if (s.snr_db < 25) snr_factor = 0.45;
    else if (s.snr_db < 35) snr_factor = 0.75;
    s.tx_rate_mbps = static_cast<std::uint32_t>(
        static_cast<double>(base) * width_factor * snr_factor);
    return s;
}

// ---------------------------------------------------------------- JSON

std::string ConnectResult::to_json() const {
    json::Writer w;
    w.boolean("ok", ok);
    w.str("final_state", to_string(final_state));
    w.str("fault", to_string(fault));
    w.integer("status_code", static_cast<std::int64_t>(status));
    w.str("status_name", to_string(status));
    w.integer("reason_code", static_cast<std::int64_t>(reason));
    w.str("reason_name", to_string(reason));
    w.str("failed_at", to_string(failed_at));
    w.str("message", message);
    w.str("bssid", bssid);
    w.str("ip_address", ip_address);
    json::Writer t;
    t.integer("scan_ms", static_cast<std::int64_t>(timings.scan_ms));
    t.integer("auth_ms", static_cast<std::int64_t>(timings.auth_ms));
    t.integer("assoc_ms", static_cast<std::int64_t>(timings.assoc_ms));
    t.integer("fourway_ms", static_cast<std::int64_t>(timings.fourway_ms));
    t.integer("dhcp_ms", static_cast<std::int64_t>(timings.dhcp_ms));
    t.integer("total_ms", static_cast<std::int64_t>(timings.total_ms));
    w.raw("timings", t.build());
    return w.build();
}

std::string LinkStats::to_json() const {
    json::Writer w;
    w.integer("rssi_dbm", rssi_dbm);
    w.integer("noise_dbm", noise_dbm);
    w.integer("snr_db", snr_db);
    w.integer("channel", channel);
    w.integer("width_mhz", width_mhz);
    w.integer("tx_rate_mbps", tx_rate_mbps);
    w.integer("tx_frames", static_cast<std::int64_t>(tx_frames));
    w.integer("rx_frames", static_cast<std::int64_t>(rx_frames));
    w.integer("tx_retries", static_cast<std::int64_t>(tx_retries));
    w.num("retry_rate", retry_rate);
    return w.build();
}

std::string StateMachine::session_summary_json() const {
    json::Writer w;
    w.str("ssid", config_.ssid);
    w.str("security", to_string(config_.security));
    w.str("band", to_string(config_.band));
    w.integer("channel", config_.channel);
    w.integer("width_mhz", config_.width);
    w.str("phy", to_string(config_.phy));
    w.integer("seed", static_cast<std::int64_t>(config_.seed));
    w.str("fault", to_string(config_.fault.fault));
    w.num("fault_probability", config_.fault.probability);
    w.str("state", to_string(state_));
    w.str("sta_mac", mac_to_string(sta_));
    w.str("bssid", mac_to_string(bssid_));
    w.integer("virtual_time_ms", static_cast<std::int64_t>(clock_.now_ms()));
    w.integer("frames_captured", static_cast<std::int64_t>(pcap_.frames_written()));
    w.integer("log_lines", static_cast<std::int64_t>(logger_.records().size()));
    w.raw("result", last_result_.to_json());
    w.raw("stats", stats().to_json());
    w.str_array("transitions", transition_history_);
    return w.build();
}

}  // namespace airframe
