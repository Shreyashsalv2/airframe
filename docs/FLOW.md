# How it all works — the flow, start to end

A plain-language walkthrough of what happens when you run the test suite.
Written as a teaching reference; for the *why* behind each decision see
[`ARCHITECTURE.md`](../ARCHITECTURE.md).

---

## First, the thing that confuses everyone

There are **two** devices you can test, and you pick one with a flag.

| | `--dut=sim` | `--dut=macos` |
|---|---|---|
| Analogy | a **flight simulator** | a **real aircraft** |
| What it is | a C++ program pretending to be a Wi-Fi device | your MacBook's actual Wi-Fi chip |
| Radio waves? | none | real |
| The router | invented (`airframe-test-ap`, doesn't exist) | your actual router |
| Can you make it fail on command? | **yes — this is the whole point** | no |
| Works with Wi-Fi off? | yes | no |

**The `.pcap` files the simulator writes are fake.** A flight simulator can produce a
black-box recording of a crash that never happened — the file is genuine and real tools
open it normally, but no aircraft moved. Same here: the bytes follow the 802.11 rulebook
exactly, and Wireshark cannot tell, but no radio ever transmitted.

**Why fake it at all?** You can order the simulator to fail. You cannot order your router
to fail. Testing "what happens when the handshake times out" needs a failure on demand,
repeatable, identical every time.

---

## Virtual time — "the simulator never sleeps"

A real Wi-Fi connection takes ~2 seconds. Two ways to simulate that:

- **sleep for real** — honest, and agonisingly slow
- **move a counter** — `clock += 1200` and claim 1.2s passed

The simulator does the second, exactly like a video game's day-night cycle. Measured:
**31.8 virtual seconds in 0.09 real seconds**, about 350× faster.

This matters more than it looks: because building a whole device per test is cheap,
every test can afford its **own** simulator. Isolation is normally the expensive choice;
here it costs milliseconds, so nobody is ever tempted to trade it away.

---

## The nine stages

### 1. You type the command
```bash
pytest --dut=sim tests/connectivity/
```

### 2. pytest loads its configuration
- `pyproject.toml` — settings and the list of legal marker names
- `tests/conftest.py` — all the fixtures
- `tests/plugin.py` — registers the `--dut` flag and the database writer

### 3. Collection — "what tests exist?"
Walks the folder, finds every `test_*` function, expands `@parametrize` (one function can
become 94 tests), and skips anything this backend cannot do — with the reason stated.

### 4. Session setup — once for the whole run
`backend_name = "sim"` · `seed = 42` · `artifact_root` · open SQLite, create a run row.

### 5. For each test — the fork

Function-scoped fixtures are built first (`artifact_dir`, then `dut`). Then
`backend_name` decides the path:

**Path A — `--dut=sim`**
1. `subprocess.Popen("sim/build/airframe-sim")` launches a C++ program
2. C++ prints `AIRFRAME_SIM_LISTENING port=64690`
3. Python opens a socket to that port
4. test calls `dut.connect()` → sends `{"cmd":"connect"}` over the socket
5. the C++ state machine runs: `IDLE → SCANNING → AUTHENTICATING → ASSOCIATING →
   FOURWAY → DHCP`, all in virtual time
6. it writes `sim.log` (what it "thought") and `sim.pcap` (fake frames, real format)
7. replies `{"ok":false,"reason_code":15,...}`

**Path B — `--dut=macos`**
1. nothing to launch — your Wi-Fi chip is already running
2. runs `system_profiler SPAirPortDataType`
3. macOS reports what your real chip is doing *right now*
4. Python parses that text into the same object shape

**Both paths produce the same `ConnectResult` object.** That is precisely why one test
works against both.

### 6. The assertions run
```python
assert result.reason_code == 15
```

### 7. The plugin records what happened
Writes a row to SQLite — test name, outcome, duration, attempt number, markers. On
failure it also copies the `.log` and `.pcap` into that test's folder so the evidence
survives.

### 8. Teardown — reverse order
Last built, first destroyed. `dut.close()` kills the C++ process; `artifact_dir` is
deleted if the test passed and **kept if it failed**, because that is exactly when you
need the evidence.

Then back to stage 5 for the next test.

### 9. Session teardown
Session fixtures released, the run row marked finished, results printed — with flaky
tests listed under their own heading rather than quietly counted as passes.

### Later — the analysis layers
Everything above just *stores evidence*. These read it back:

```
make ml      cluster many failures into a few distinct bugs
make triage  an LLM reads the evidence and writes a root cause
make report  HTML dashboard
MCP server   an AI assistant can query all of it conversationally
```

---

## One sentence

> pytest reads your flag → builds a fake or real Wi-Fi device → the test asks it to
> connect → it either runs a C++ state machine or queries your actual chip → both return
> the same `ConnectResult` → assertions run → results go to a database → everything is
> torn down in reverse.
