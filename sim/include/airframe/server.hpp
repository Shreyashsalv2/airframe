// Line-delimited JSON control server.
//
// The Python DUT backend spawns this binary with `--serve` and drives it over a
// TCP socket. One JSON object per line, one response per request:
//
//   -> {"cmd":"connect","ssid":"lab-ap","security":"wpa3_sae","band":"5GHz"}
//   <- {"ok":true,"final_state":"CONNECTED","timings":{...}}
//
// Newline framing rather than length-prefixing because the protocol is small and
// newline-delimited JSON is trivially debuggable — you can drive the whole DUT
// from `nc` by hand, which matters a great deal when something is broken.
#pragma once

#include <string>

#include "airframe/state_machine.hpp"

namespace airframe {

// Handles one request line. Pure: no I/O, so it is unit-testable directly.
std::string handle_command(StateMachine*& sm, SimConfig& base_config, const std::string& line,
                           bool& should_quit);

// Blocking accept loop. Returns the process exit code.
int serve(SimConfig base_config, const std::string& host, int port);

}  // namespace airframe
