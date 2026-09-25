# airframe

**A wireless connectivity test automation and AI triage platform.**

A complete 802.11 quality-engineering rig: a simulated Wi-Fi device under test, a
pytest framework that drives it *and* real hardware through one interface, packet
forensics validated against Wireshark, network KPI measurement with regression
detection, log template mining, ML failure clustering, an LLM triage agent, and an MCP
server that lets an AI assistant operate the whole lab.

```
548 Python tests · 99 C++ tests · 427/427 captures agree with tshark
```

---

## What problem it solves

When a Wi-Fi connection fails, the evidence is scattered: a driver log says the
handshake timed out, a packet capture shows a frame was retransmitted four times, a
latency graph shows a spike. Individually each is ambiguous. A human has to open three
tools and correlate them by hand, and then do it again for the next two hundred
failures in the run.

airframe automates that end to end:

```
  a test fails
      ↓
  logs + packet capture + KPI samples, all on one clock
      ↓
  802.11 forensics: which stage broke, and what IEEE code the AP gave
      ↓
  clustering: 200 red tests collapse into 4 distinct bugs
      ↓
  triage: root cause, confidence, suggested owner, and a filled-in bug report
```

---

## Architecture

The spine is one idea: **one test suite, many backends.**

```
      pytest suite  ──uses──►  DUT interface  ──┬──►  SimDUT ───► C++ simulator (TCP/JSON)
   (the deliverable)                            └──►  MacOSDUT ─► real Wi-Fi + real network
                │                                                   │
                │   emits: logs + 802.11 pcap + KPI samples ◄────────┘
                ▼
         SQLite store (runs, results, kpi_samples, baselines, templates, triage)
                │
    ┌───────────┼───────────┬──────────────┬────────────────┐
    ▼           ▼           ▼              ▼                ▼
 log mining  pcap 802.11  KPI regression  ML failure     LLM triage agent
 (Drain)     forensics    detection       clustering     (Groq / Mock)
                                    │
                                    ▼
                         HTML dashboard  +  MCP server (14 tools)
```

Tests are written against an abstract `DUT` interface, so the identical `pytest` run
targets either a deterministic C++ simulator or this machine's actual Wi-Fi card:

```bash
pytest --dut=sim      # deterministic, injectable faults, runs anywhere
pytest --dut=macos    # the real radio: real RSSI, real throughput, real latency
```

Backends are genuinely unequal — a simulator can be ordered to fail its 4-way
handshake and a real Wi-Fi card cannot — so each one **declares its capabilities** and
tests that need something unavailable are skipped with the reason stated. The simulator
advertises 8 capabilities; real hardware advertises 2. See
[ARCHITECTURE.md](ARCHITECTURE.md) for why that is the right answer and what the two
wrong answers cost.

---

## Quickstart

```bash
make setup      # venv + dependencies (needs Python 3.11+, cmake)
make sim        # build the C++ simulator
make corpus     # generate the capture/log corpus (deterministic)
make test       # 548 tests against the simulator
make verify     # the whole pipeline, end to end
```

Requires `cmake` and Python 3.11+. `tshark` and `iperf3` are optional and improve the
packet-analysis and throughput layers; everything degrades with a stated reason when
they are absent. No API key is needed — the triage agent falls back to a deterministic
offline provider.

### Try the interesting parts

```bash
# Simulate a WPA3 connection whose 4-way handshake times out
./sim/build/airframe-sim --scenario wpa3 --fault FOURWAY_M3_TIMEOUT \
    --seed 42 --pcap /tmp/f.pcap --log /tmp/f.log

# Reconstruct what happened from the packet capture alone
python -m airframe.pcap.assoc /tmp/f.pcap

# See logs and packets interleaved on one clock
python -m airframe.logs.timeline --log /tmp/f.log --pcap /tmp/f.pcap

# Measure your actual network against Indian ISP endpoints
make kpi-quick

# Collapse every corpus failure into distinct bugs
make ml

# Ask an LLM to triage a failure
make triage
```

---

## What each layer does

| Layer | Directory | What it is |
| --- | --- | --- |
| **DUT simulator** | `sim/` | C++17. An 802.11 station state machine with 12 injectable faults. Emits genuine `.pcap` files and `wifid`-style logs. Fully deterministic: the same seed reproduces byte-identical output. Uses virtual time, so a 2.4-second association completes in microseconds. |
| **Abstraction** | `src/airframe/dut/` | The `DUT` protocol plus two backends. The most important interface in the project. |
| **Test framework** | `tests/` | The pytest suite and a custom plugin: capability gating, result persistence, and retries that **record flakes rather than hiding them**. |
| **Packet forensics** | `src/airframe/pcap/` | Dissects 802.11, reconstructs the association sequence, names the failing stage and its IEEE code. Cross-validated against `tshark`. Includes Scapy synthesis of attack and malformed frames for negative testing. |
| **Network KPIs** | `src/airframe/kpi/` | Latency, DNS, TCP, TLS, TTFB, throughput and loss against Indian ISP resolvers and CDN edges. Robust statistics; regression detection against learned baselines. |
| **Log analysis** | `src/airframe/logs/` | A from-scratch Drain template miner (7,286 lines → 44 templates) and a correlator that puts logs, frames and KPIs on one monotonic clock. |
| **ML** | `src/airframe/ml/` | Failure-signature clustering, IsolationForest KPI anomaly detection, and flake classification that distinguishes *flaky* from *fixed* from *regressed*. |
| **AI triage** | `src/airframe/triage/` | A provider-agnostic LLM agent with read-only tools that iterates toward a root cause and must cite evidence. |
| **MCP server** | `src/airframe/mcp/` | 14 tools exposing the rig to an AI assistant. Read-only by default. |
| **Dashboard** | `src/airframe/report/` | A self-contained HTML report. |

---

## Results

Measured, not asserted — every number below is reproducible with `make verify`.

| | |
| --- | --- |
| **Dissector accuracy** | 427/427 captures agree with `tshark` frame-for-frame, including deliberately malformed and hostile ones |
| **Log compression** | 7,286 log lines → 44 templates (99.4%) |
| **Failure clustering** | 174 failures → 10 clusters; homogeneity 1.00, completeness 1.00, ARI 1.00 against known injected faults |
| **Triage accuracy** | 10/10 correct owner attribution across every injected fault |
| **Determinism** | identical `.pcap`, `.log` and JSON output for a given seed |
| **Tests** | 548 Python + 99 C++, the latter clean under ASan and UBSan |

On the perfect clustering score: that reflects unusually clean data — a deterministic
simulator and ten faults engineered to be distinguishable. Real production failures
overlap and arrive with missing artifacts; a realistic figure there would be lower and
would involve a human reviewing cluster exemplars. What the score does demonstrate is
that the pipeline is wired up correctly.

---

## The build journal

[`BUILD_JOURNAL.md`](BUILD_JOURNAL.md) records 19 real bugs hit while building this,
each with the **wrong assumption I started from** — which is the part memory deletes
and the part that actually teaches. A sample:

- `tshark` reported "Malformed Packet" on my WPA3 frames and my first instinct was to
  explain it away. It was right: I had announced SAE and sent an Open System body.
- The interop matrix found a rule missing from my own simulator — it accepted 320 MHz
  on Wi-Fi 6, which the spec forbids. My first instinct was to weaken the test.
- A 9× throughput collapse passed the regression detector cleanly. Not a tuning
  problem: with 51% natural variance, no z-threshold can separate it from noise.
- My flake detector listed every bug I had fixed that day as a problem, because
  `flake_rate` measures inconsistency and inconsistency is not flakiness.

---

## Documents

| File | What it is |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Every significant decision, the alternative rejected, and what it cost |
| [BUILD_JOURNAL.md](BUILD_JOURNAL.md) | 19 real bugs, honestly recorded |
| [TEACHING_PLAN.md](TEACHING_PLAN.md) | A 3-day curriculum for learning this codebase from zero |
| [CHEATSHEET.md](CHEATSHEET.md) | ~40 interview questions about this project, with answers |
| [PITCH.md](PITCH.md) | How to present it in 60 seconds |

## Commands

`make help` lists everything. The ones worth knowing:

```
make test          548 tests against the simulator
make test-macos    the real-hardware subset against this Mac's Wi-Fi
make test-flaky    demonstrate flake recording
make sim-test      99 C++ unit tests
make sim-asan      the C++ tests under ASan + UBSan
make corpus        regenerate captures and logs (deterministic)
make pcap          cross-validate the dissector against tshark
make kpi           measure the network and check for regressions
make ml            failure clustering + flake analysis
make triage        LLM triage scored against known faults
make mcp           list the MCP tools
make report        build the dashboard
make verify        all of the above, end to end
```

## Licence

Built as a portfolio project. Use it however you like.
