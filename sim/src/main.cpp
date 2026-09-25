// airframe-sim — CLI entry point.
//
// Two modes:
//   one-shot   ./airframe-sim --scenario wpa3 --fault FOURWAY_M3_TIMEOUT --seed 42
//   server     ./airframe-sim --serve --port 0
//
// One-shot is for humans and for generating capture/log fixtures; server mode is
// how the Python test framework drives the DUT.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

#include "airframe/server.hpp"
#include "airframe/state_machine.hpp"

namespace {

using namespace airframe;

void usage() {
    std::printf(R"(airframe-sim — 802.11 station simulator (Device Under Test)

USAGE
  airframe-sim [options]
  airframe-sim --serve [--host 127.0.0.1] [--port 0]

CONNECTION OPTIONS
  --ssid NAME          network name              (default: airframe-test-ap)
  --security MODE      open | wpa2_psk | wpa3_sae | wpa2_enterprise
  --band BAND          2.4GHz | 5GHz | 6GHz      (default: 5GHz)
  --channel N          channel number            (default: 36)
  --width MHZ          20 | 40 | 80 | 160 | 320  (default: 80)
  --phy GEN            11n | 11ac | 11ax | 11be  (default: 11ax)

FAULT INJECTION
  --fault NAME         inject a named fault      (default: NONE)
  --probability P      fire the fault with probability P (default: 1.0 = always)
  --code N             override the status/reason code the fault reports

DETERMINISM
  --seed N             RNG seed                  (default: 42)

OUTPUT
  --log PATH           write structured logs to PATH
  --pcap PATH          write an 802.11 capture to PATH
  --summary PATH       write the JSON session summary to PATH
  --verbose            mirror logs to stderr
  --run-ms N           stay connected for N virtual ms after connecting
  --roam               perform a roam after connecting

OTHER
  --scenario NAME      preset: open | wpa2 | wpa3 | enterprise | wifi6e | legacy
  --list-faults        print every fault name and exit
  --serve              run the JSON control server
  --help               this text

EXIT STATUS
  0  connected successfully
  1  connection failed (including an injected fault firing as intended)
  2  bad usage
)");
}

bool apply_scenario(const std::string& name, SimConfig& c) {
    if (name == "open") {
        c.security = Security::Open;  c.band = Band::Band2_4GHz; c.channel = 6;
        c.width = 20; c.phy = Phy::Dot11n;
    } else if (name == "wpa2") {
        c.security = Security::Wpa2Psk; c.band = Band::Band5GHz; c.channel = 44;
        c.width = 80; c.phy = Phy::Dot11ac;
    } else if (name == "wpa3") {
        c.security = Security::Wpa3Sae; c.band = Band::Band5GHz; c.channel = 36;
        c.width = 80; c.phy = Phy::Dot11ax;
    } else if (name == "enterprise") {
        c.security = Security::Wpa2Enterprise; c.band = Band::Band5GHz; c.channel = 149;
        c.width = 40; c.phy = Phy::Dot11ac;
    } else if (name == "wifi6e") {
        c.security = Security::Wpa3Sae; c.band = Band::Band6GHz; c.channel = 37;
        c.width = 160; c.phy = Phy::Dot11ax;
    } else if (name == "legacy") {
        c.security = Security::Wpa2Psk; c.band = Band::Band2_4GHz; c.channel = 1;
        c.width = 20; c.phy = Phy::Dot11n;
    } else {
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    SimConfig cfg;
    std::string summary_path;
    std::string host = "127.0.0.1";
    int  port     = 0;
    bool serve_mode = false;
    bool do_roam  = false;
    std::uint64_t run_ms = 0;

    auto need = [&](int& i) -> const char* {
        if (i + 1 >= argc) {
            std::fprintf(stderr, "error: %s requires a value\n", argv[i]);
            std::exit(2);
        }
        return argv[++i];
    };

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--list-faults") {
            for (const auto& f : all_fault_names()) std::printf("%s\n", f.c_str());
            return 0;
        }
        else if (a == "--ssid")        cfg.ssid = need(i);
        else if (a == "--channel")     cfg.channel = static_cast<std::uint8_t>(std::atoi(need(i)));
        else if (a == "--width")       cfg.width = static_cast<std::uint16_t>(std::atoi(need(i)));
        else if (a == "--seed")        cfg.seed = std::strtoull(need(i), nullptr, 10);
        else if (a == "--probability") cfg.fault.probability = std::atof(need(i));
        else if (a == "--code")        cfg.fault.code = static_cast<std::uint16_t>(std::atoi(need(i)));
        else if (a == "--log")         cfg.log_path = need(i);
        else if (a == "--pcap")        cfg.pcap_path = need(i);
        else if (a == "--summary")     summary_path = need(i);
        else if (a == "--verbose")     cfg.log_stderr = true;
        else if (a == "--serve")       serve_mode = true;
        else if (a == "--roam")        do_roam = true;
        else if (a == "--host")        host = need(i);
        else if (a == "--port")        port = std::atoi(need(i));
        else if (a == "--run-ms")      run_ms = std::strtoull(need(i), nullptr, 10);
        else if (a == "--security") {
            if (!parse_security(need(i), cfg.security)) {
                std::fprintf(stderr, "error: unknown security mode '%s'\n", argv[i]);
                return 2;
            }
        }
        else if (a == "--band") {
            if (!parse_band(need(i), cfg.band)) {
                std::fprintf(stderr, "error: unknown band '%s'\n", argv[i]);
                return 2;
            }
        }
        else if (a == "--phy") {
            if (!parse_phy(need(i), cfg.phy)) {
                std::fprintf(stderr, "error: unknown PHY '%s'\n", argv[i]);
                return 2;
            }
        }
        else if (a == "--fault") {
            if (!parse_fault(need(i), cfg.fault.fault)) {
                std::fprintf(stderr, "error: unknown fault '%s' (try --list-faults)\n", argv[i]);
                return 2;
            }
        }
        else if (a == "--scenario") {
            if (!apply_scenario(need(i), cfg)) {
                std::fprintf(stderr, "error: unknown scenario '%s'\n", argv[i]);
                return 2;
            }
        }
        else {
            std::fprintf(stderr, "error: unknown option '%s' (try --help)\n", a.c_str());
            return 2;
        }
    }

    if (serve_mode) return serve(cfg, host, port);

    StateMachine sm(cfg);
    const ConnectResult r = sm.connect();

    if (r.ok && do_roam)  sm.roam();
    if (r.ok && run_ms)   sm.run_connected(run_ms);
    if (sm.state() == State::Connected) sm.disconnect();

    const std::string summary = sm.session_summary_json();
    if (!summary_path.empty()) {
        std::ofstream out(summary_path);
        out << summary << '\n';
    }
    std::printf("%s\n", summary.c_str());
    return r.ok ? 0 : 1;
}
