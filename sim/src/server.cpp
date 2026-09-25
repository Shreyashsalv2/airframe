#include "airframe/server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include "airframe/json.hpp"

namespace airframe {
namespace {

std::string error_response(const std::string& msg) {
    json::Writer w;
    w.boolean("ok", false);
    w.str("error", msg);
    return w.build();
}

// Apply any overrides present in the request to a copy of the base config.
SimConfig config_from(const SimConfig& base, const json::Value& req, std::string& err) {
    SimConfig c = base;
    if (req.has("ssid"))  c.ssid = req.get_str("ssid", c.ssid);
    if (req.has("seed"))  c.seed = static_cast<std::uint64_t>(req.get_int("seed",
                                       static_cast<std::int64_t>(c.seed)));
    if (req.has("channel")) c.channel = static_cast<std::uint8_t>(req.get_int("channel", c.channel));
    if (req.has("width"))   c.width   = static_cast<std::uint16_t>(req.get_int("width", c.width));

    if (req.has("security") && !parse_security(req.get_str("security"), c.security)) {
        err = "unknown security: " + req.get_str("security");
        return c;
    }
    if (req.has("band") && !parse_band(req.get_str("band"), c.band)) {
        err = "unknown band: " + req.get_str("band");
        return c;
    }
    if (req.has("phy") && !parse_phy(req.get_str("phy"), c.phy)) {
        err = "unknown phy: " + req.get_str("phy");
        return c;
    }
    if (req.has("fault")) {
        Fault f = Fault::None;
        if (!parse_fault(req.get_str("fault"), f)) {
            err = "unknown fault: " + req.get_str("fault");
            return c;
        }
        c.fault.fault = f;
        c.fault.probability = req.has("probability") ? req.get_num("probability", 1.0) : 1.0;
        c.fault.code = static_cast<std::uint16_t>(req.get_int("code", 0));
    }
    if (req.has("log_path"))  c.log_path  = req.get_str("log_path");
    if (req.has("pcap_path")) c.pcap_path = req.get_str("pcap_path");
    return c;
}

}  // namespace

std::string handle_command(StateMachine*& sm, SimConfig& base_config, const std::string& line,
                           bool& should_quit) {
    json::Value req;
    std::string perr;
    if (!json::parse(line, req, perr)) return error_response("bad JSON: " + perr);
    if (!req.is_object())              return error_response("request must be a JSON object");

    const std::string cmd = req.get_str("cmd");
    if (cmd.empty()) return error_response("missing 'cmd'");

    // ---- commands that do not need a live state machine ----
    if (cmd == "ping") {
        json::Writer w;
        w.boolean("ok", true);
        w.str("pong", "airframe-sim");
        return w.build();
    }
    if (cmd == "quit" || cmd == "shutdown") {
        should_quit = true;
        json::Writer w;
        w.boolean("ok", true);
        w.str("bye", "airframe-sim");
        return w.build();
    }
    if (cmd == "capabilities") {
        json::Writer w;
        w.boolean("ok", true);
        w.str_array("faults", all_fault_names());
        w.str_array("bands", {"2.4GHz", "5GHz", "6GHz"});
        w.str_array("security", {"open", "wpa2_psk", "wpa3_sae", "wpa2_enterprise"});
        w.str_array("phy", {"11n", "11ac", "11ax", "11be"});
        w.boolean("fault_injection", true);
        w.boolean("deterministic", true);
        w.boolean("packet_capture", true);
        return w.build();
    }

    // ---- session lifecycle ----
    if (cmd == "open" || cmd == "configure") {
        std::string err;
        SimConfig c = config_from(base_config, req, err);
        if (!err.empty()) return error_response(err);
        base_config = c;
        delete sm;
        sm = new StateMachine(c);
        json::Writer w;
        w.boolean("ok", true);
        w.str("state", to_string(sm->state()));
        w.str("bssid", sm->bssid_string());
        return w.build();
    }

    if (!sm) {
        // Implicit open keeps the protocol forgiving; the Python client always
        // sends an explicit `open`, but a human poking at it with `nc` should not
        // have to know that.
        std::string err;
        SimConfig c = config_from(base_config, req, err);
        if (!err.empty()) return error_response(err);
        sm = new StateMachine(c);
    }

    try {
        if (cmd == "scan") {
            const auto entries = sm->scan();
            std::string arr = "[";
            for (std::size_t i = 0; i < entries.size(); ++i) {
                if (i) arr += ",";
                json::Writer e;
                e.str("ssid", entries[i].ssid);
                e.str("bssid", entries[i].bssid);
                e.str("band", to_string(entries[i].band));
                e.integer("channel", entries[i].channel);
                e.integer("width_mhz", entries[i].width);
                e.str("phy", to_string(entries[i].phy));
                e.str("security", to_string(entries[i].security));
                e.integer("rssi_dbm", entries[i].rssi_dbm);
                arr += e.build();
            }
            arr += "]";
            json::Writer w;
            w.boolean("ok", true);
            w.raw("networks", arr);
            w.integer("count", static_cast<std::int64_t>(entries.size()));
            w.str("state", to_string(sm->state()));
            return w.build();
        }

        if (cmd == "connect") {
            const ConnectResult r = sm->connect();
            json::Writer w;
            w.boolean("ok", r.ok);
            w.raw("result", r.to_json());
            w.str("state", to_string(sm->state()));
            w.integer("virtual_time_ms", static_cast<std::int64_t>(sm->now_ms()));
            return w.build();
        }

        if (cmd == "disconnect") {
            ReasonCode rc = ReasonCode::DeauthLeaving;
            if (req.has("reason")) rc = static_cast<ReasonCode>(req.get_int("reason", 3));
            sm->disconnect(rc);
            json::Writer w;
            w.boolean("ok", true);
            w.str("state", to_string(sm->state()));
            return w.build();
        }

        if (cmd == "roam") {
            const ConnectResult r = sm->roam();
            json::Writer w;
            w.boolean("ok", r.ok);
            w.raw("result", r.to_json());
            w.str("state", to_string(sm->state()));
            return w.build();
        }

        if (cmd == "run") {
            const std::uint64_t ms = static_cast<std::uint64_t>(req.get_int("ms", 1000));
            const bool still_up = sm->run_connected(ms);
            json::Writer w;
            w.boolean("ok", still_up);
            w.str("state", to_string(sm->state()));
            w.raw("stats", sm->stats().to_json());
            w.integer("virtual_time_ms", static_cast<std::int64_t>(sm->now_ms()));
            return w.build();
        }

        if (cmd == "state") {
            json::Writer w;
            w.boolean("ok", true);
            w.str("state", to_string(sm->state()));
            w.integer("virtual_time_ms", static_cast<std::int64_t>(sm->now_ms()));
            return w.build();
        }

        if (cmd == "stats") {
            json::Writer w;
            w.boolean("ok", true);
            w.raw("stats", sm->stats().to_json());
            w.str("state", to_string(sm->state()));
            return w.build();
        }

        if (cmd == "summary") {
            json::Writer w;
            w.boolean("ok", true);
            w.raw("summary", sm->session_summary_json());
            return w.build();
        }

        if (cmd == "inject_fault") {
            Fault f = Fault::None;
            if (!parse_fault(req.get_str("fault", "NONE"), f))
                return error_response("unknown fault: " + req.get_str("fault"));
            FaultSpec spec;
            spec.fault = f;
            spec.probability = req.has("probability") ? req.get_num("probability", 1.0) : 1.0;
            spec.code = static_cast<std::uint16_t>(req.get_int("code", 0));
            sm->set_fault(spec);
            json::Writer w;
            w.boolean("ok", true);
            w.str("fault", to_string(f));
            w.num("probability", spec.probability);
            return w.build();
        }

        if (cmd == "reset") {
            sm->reset();
            json::Writer w;
            w.boolean("ok", true);
            w.str("state", to_string(sm->state()));
            return w.build();
        }

        return error_response("unknown command: " + cmd);

    } catch (const IllegalTransition& e) {
        // Surfaced to the client rather than crashing the process: an illegal
        // transition is a bug in the *caller*, and the caller is the thing under
        // test, so it must see a clean error.
        json::Writer w;
        w.boolean("ok", false);
        w.str("error", e.what());
        w.str("error_kind", "illegal_transition");
        w.str("state", to_string(sm->state()));
        return w.build();
    } catch (const std::exception& e) {
        return error_response(std::string("internal error: ") + e.what());
    }
}

int serve(SimConfig base_config, const std::string& host, int port) {
    const int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::perror("socket");
        return 1;
    }

    int yes = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        std::fprintf(stderr, "bad bind address: %s\n", host.c_str());
        ::close(listen_fd);
        return 1;
    }

    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        ::close(listen_fd);
        return 1;
    }
    if (::listen(listen_fd, 4) < 0) {
        std::perror("listen");
        ::close(listen_fd);
        return 1;
    }

    // Report the bound port on stdout before anything else. With port 0 the OS
    // picks a free port, and the Python side reads this line to learn which one.
    // Hardcoding a port is how test suites end up flaky on busy machines.
    sockaddr_in bound{};
    socklen_t blen = sizeof(bound);
    ::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&bound), &blen);
    std::printf("AIRFRAME_SIM_LISTENING port=%d\n", ntohs(bound.sin_port));
    std::fflush(stdout);

    StateMachine* sm = nullptr;
    bool quit = false;

    while (!quit) {
        const int fd = ::accept(listen_fd, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR) continue;
            std::perror("accept");
            break;
        }
        int nodelay = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        // Read until newline, dispatch, write response. The buffer persists
        // across reads because TCP is a byte stream: one read() can return half a
        // line or three lines, and assuming otherwise is the single most common
        // socket bug there is.
        std::string buf;
        char chunk[4096];
        bool client_open = true;

        while (client_open && !quit) {
            const ssize_t n = ::read(fd, chunk, sizeof(chunk));
            if (n <= 0) break;
            buf.append(chunk, static_cast<std::size_t>(n));

            std::size_t nl;
            while ((nl = buf.find('\n')) != std::string::npos) {
                std::string line = buf.substr(0, nl);
                buf.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) continue;

                const std::string resp = handle_command(sm, base_config, line, quit);
                const std::string out = resp + "\n";
                ssize_t written = 0;
                while (written < static_cast<ssize_t>(out.size())) {
                    const ssize_t w = ::write(fd, out.data() + written,
                                              out.size() - static_cast<std::size_t>(written));
                    if (w <= 0) { client_open = false; break; }
                    written += w;
                }
                if (quit) break;
            }
        }
        ::close(fd);
    }

    delete sm;
    ::close(listen_fd);
    return 0;
}

}  // namespace airframe
