# Build Journal

Real problems hit while building `airframe`, in the order they happened.

Each entry follows the same shape: **symptom → what I first assumed → what was actually
wrong → the fix → the transferable lesson.** Dead ends are included, because the dead ends
are where the learning is. Nothing here is reconstructed after the fact.

> **Why this file exists.** "Tell me about a bug you debugged" is asked in essentially every
> engineering interview, and the honest answer requires having written the details down at
> the time. Memory smooths over the useful parts — specifically, it deletes the wrong
> assumption you started with, which is the only part the interviewer actually cares about.

---

## #1 — System Python was too old for the project to exist

**Symptom.** `python3 --version` on this machine reported **3.9.6**.

**What I first assumed.** That it was fine. 3.9 runs most code, and my instinct was to
lower the floor in `pyproject.toml` to `>=3.9` and move on.

**What was actually wrong.** Two hard blockers, neither negotiable:

1. The **MCP SDK requires Python ≥3.10.** MCP is a headline requirement of this project, so
   3.9 doesn't just inconvenience the build, it deletes a feature.
2. Modern type syntax (`X | None`, `list[str]` in annotations evaluated at runtime,
   `Self`, `typing.Protocol` improvements) is used throughout the abstraction layer. On 3.9
   that becomes `Optional[X]` and `List[str]` noise everywhere — which matters because this
   codebase is a *teaching* artifact, and the version you learn is the version you'll write
   at work.

Worth being precise about *why* macOS ships 3.9: it's there for Apple's own tooling, it is
deliberately frozen, and you should never build a project against it or install packages
into it. On modern macOS `pip install` into the system Python is blocked outright
(`externally-managed-environment`) for exactly this reason.

**The fix.** `brew install python@3.13`, then a project-local virtualenv:

```bash
/opt/homebrew/bin/python3.13 -m venv .venv
./.venv/bin/python -m pip install -e ".[dev]"
```

Note the venv is created with an **explicit absolute path to the interpreter**, not with
whatever `python3` happens to resolve to. That one detail is the difference between a build
that works on any machine and a build that works on the machine that made it.

**Transferable lesson.** Pin the language version *before* writing code, and derive the
floor from your hardest dependency rather than from what's already installed. "It works on
my machine" nearly always decodes to "I inherited an interpreter I never chose."

---

## #2 — `cmake`, `tshark` and `iperf3` were all absent, but they are not equally important

**Symptom.** Only `clang++`, `git`, `sqlite3` and `brew` were present. No `cmake`, no
`tshark`, no `iperf3`.

**What I first assumed.** That these were four items on one shopping list.

**What was actually wrong.** They fall into two categories, and conflating them would have
made the project fragile:

- `cmake` is a **hard dependency**. Without it there is no C++ build at all.
- `tshark` and `iperf3` are **capability upgrades**. They make the packet-analysis and
  throughput layers better, but if the project *requires* them then anyone cloning the repo
  hits a wall, and CI (which has neither) can never run.

**The fix.** Install all four, but architect so that only `cmake` is mandatory. Every
optional tool is probed at runtime and has a documented fallback:

| Tool | Used for | Fallback when missing |
| --- | --- | --- |
| `tshark` | Independent cross-check of our own 802.11 parser | Our parser runs alone; the cross-check test `skip`s with a stated reason |
| `iperf3` | Sustained-throughput measurement | HTTP range-download throughput probe |

**Transferable lesson.** Sort dependencies into *required* and *enriching* on day one, and
make the enriching ones degrade loudly but safely — `skip` with a reason, never a silent
pass and never a hard crash. A test that quietly passes because a tool was missing is worse
than no test, because it reports confidence it never earned.

---

## #3 — `pip install` resolved pytest 9, not the pytest 8 I designed against

**Symptom.** `pyproject.toml` asked for `pytest>=8.0`; the resolver installed **9.1.1**.

**What I first assumed.** Harmless — a minor-version drift I could ignore.

**What was actually wrong.** pytest 9 is a **major** release, and major releases are where
long-deprecated APIs finally get deleted. The custom plugin in `tests/plugin.py` leans on
hook behaviour (`pytest_runtest_makereport`, `pytest_collection_modifyitems`) that survived
the cut, but several adjacent patterns did not — nose-style `setup`/`teardown` methods, the
old `tryfirst`/`trylast` marker spellings, and some `Node` constructor signatures. Writing
the plugin from pytest-8-era memory would have produced code that fails on the version
actually installed.

**The fix.** Verify the installed version *before* writing plugin code, and write against
that. `--strict-markers` and `--strict-config` are enabled in `pyproject.toml` so that a
typo'd marker or a stale config key is a hard error rather than a silent no-op.

**Transferable lesson.** `>=` in a dependency spec is a statement about the *past*, not the
future — it tells you the oldest version that works and nothing about the newest. Check what
the resolver actually chose, then write against that. This is precisely the class of
breakage a test framework exists to catch, which makes getting it wrong in a test framework
particularly embarrassing.

---

## #4 — Two innocuous integer overloads made the build ambiguous

**Symptom.** The simulator would not compile:

```
error: call to 'kv' is ambiguous
  join({"auth timeout", kv("bssid", res.bssid), kv("timeout_ms", kAuthTimeoutMs), ...
candidate: std::string kv(const std::string&, std::uint64_t)
candidate: std::string kv(const std::string&, int)
```

**What I first assumed.** A missing include or a typo. Ambiguity errors read like
something is absent, so my first instinct was to look for what I had forgotten.

**What was actually wrong.** Nothing was missing. I had written two helper
overloads for formatting `key=value` log fields:

```cpp
std::string kv(const std::string& k, std::uint64_t v);
std::string kv(const std::string& k, int v);
```

`kAuthTimeoutMs` is a `constexpr std::uint32_t`. Converting `uint32_t` to `int`
and converting `uint32_t` to `uint64_t` are **both** integral conversions of
identical rank, so neither overload is a better match. The compiler is not being
fussy — it genuinely cannot choose, and silently picking one would be worse.

Note the shape of the trap: each overload is individually reasonable, the call
site is reasonable, and the bug only exists in the *interaction*. It also would
not have appeared if every caller had passed exactly `int` or exactly `uint64_t`.

**The fix.** One constrained template instead of an overload set, so there is
nothing to choose between:

```cpp
template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
std::string kv(const std::string& k, T v) { return k + "=" + std::to_string(v); }
```

**Transferable lesson.** Overloading on multiple integer widths invites
ambiguity, because C++'s integral conversions are mostly the same rank. When a
helper should accept "any number", say that with one template rather than
enumerating types. And read ambiguity errors as "too many candidates", not "a
missing declaration" — they point at a design smell, not an omission.

---

## #5 — `tshark` said "Malformed Packet" and I almost shipped it anyway

**Symptom.** The hand-written pcap opened correctly in `tshark`, and the whole
injected fault was legible — probe, beacon, auth, assoc, EAPOL M1, M2, M2 retried
three times, deauth. Success, apparently. Except two frames read:

```
4  Authentication, SN=3 ... [Malformed Packet]
5  Authentication, SN=4 ... [Malformed Packet]
```

**What I first assumed.** That `tshark` was being pedantic about a synthetic
capture, and that since every other frame decoded perfectly this was cosmetic. I
was about to move on. **This was the real mistake — not the code, the judgement.**

**What was actually wrong.** A genuine protocol error, and `tshark -V` said so
precisely:

```
Authentication Algorithm: Simultaneous Authentication of Equals (SAE) (3)
Authentication SEQ: 0x0001
SAE Message Type: Commit (1)
[Malformed Packet: IEEE 802.11]
```

WPA2 uses **Open System** authentication, whose frame body really is just
`algorithm | sequence | status` — six bytes, which is what I had written. WPA3
uses **SAE**, and an SAE frame body carries a payload: for a Commit that is the
finite cyclic group ID plus a scalar plus an element (for group 19 / P-256, 2 + 32
+ 64 bytes). I had set the algorithm field to 3 and then sent no payload at all.
Wireshark read the header, correctly expected an SAE Commit body, and hit the end
of the frame.

The same investigation surfaced a second error I had not been looking for: real
SAE is a **four-frame** exchange (Commit from the STA, Commit from the AP, then
Confirm in each direction) before association begins. I was emitting two frames
and calling it authenticated.

**The fix.** Real `sae_commit()` and `sae_confirm()` builders, and the full
four-frame exchange in the state machine for WPA3. Verified across all six
scenarios:

```
open 0 malformed / 8 frames      enterprise 0 malformed / 12 frames
wpa2 0 malformed / 12 frames     wifi6e     0 malformed / 14 frames
wpa3 0 malformed / 14 frames     legacy     0 malformed / 12 frames
```

**Transferable lesson.** Two lessons, and the second is the one that matters.

The technical one: when a protocol field selects a *variant*, setting that field
obliges you to produce the matching body. Announcing SAE and sending an
Open System body is not "mostly right", it is a different message.

The real one: **I had an independent oracle telling me I was wrong and my first
instinct was to explain it away.** `tshark` is a decades-old reference
implementation; when it and my 400-line frame builder disagree about IEEE 802.11,
the prior should not be that `tshark` is confused. Cross-checking against an
independent implementation is precisely why this project validates its own parser
against `tshark` — and the value of an oracle is exactly zero if you overrule it
when it is inconvenient. The bug took fifteen minutes to fix. Believing the tool
took longer.

---

## #6 — Every documented way to read macOS Wi-Fi state was wrong

**Symptom.** The real-hardware backend needs RSSI, noise, channel, width, PHY mode
and rate. The universally-documented way to get them is:

```bash
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
```

On this machine:

```
ls: .../Resources/airport: No such file or directory
```

**What I first assumed.** A wrong path — the binary moved between macOS versions,
so my first move was to go looking for it elsewhere.

**What was actually wrong.** It is not moved, it is **deleted.** `airport` lived
in a *private* framework, was formally deprecated in macOS 14, and has since been
removed. Every tutorial, StackOverflow answer and blog post more than roughly two
years old recommends a tool that no longer exists. This machine runs macOS 26.6.

So I probed what actually works, rather than trusting any more documentation:

| Command | Result on macOS 26.6 |
| --- | --- |
| `airport -I` | **Removed.** Does not exist. |
| `wdutil info` | Works, but **requires sudo** (`usage: sudo wdutil info`) |
| `networksetup -getairportnetwork en0` | Returns **"You are not associated with an AirPort network"** — while genuinely connected |
| `system_profiler -json SPAirPortDataType` | **Works, no privileges needed** |

Two of those deserve more than a table row.

`networksetup` actively lies. It reported not-associated while `system_profiler`
simultaneously reported a live 5 GHz connection on channel 149. Had I picked
`networksetup` as my source of truth — a reasonable choice, it is a documented
public tool — the backend would have reported "disconnected" on a working
machine, and I would have gone looking for the bug in my own code.

And the finding I did not anticipate at all:

```
_name = '<redacted>'
spairport_network_channel = '149 (5GHz, 80MHz)'
spairport_signal_noise = '-64 dBm / -89 dBm'
```

**The SSID is redacted, but the radio metrics are not.** On modern macOS a network
*name* is treated as location-inferring data and withheld unless the calling
process holds Location Services permission; signal strength and channel are not,
so they come through untouched.

**The fix.** `system_profiler -json` as the primary source, with dedicated
parsers for its string-formatted fields (`"149 (5GHz, 80MHz)"` →
`(149, GHZ_5, 80)`; `"-64 dBm / -89 dBm"` → `(-64, -89)`). `wdutil` is attempted
opportunistically with **`sudo -n`** — non-interactive, so it fails instantly
instead of blocking a test run on an invisible password prompt — and degrades to
`{}` when refused. The redacted SSID is reported as exactly `<redacted>` rather
than guessed at or blanked, because a backend that invents data is worse than one
that admits a gap.

One more decision worth recording. `disconnect()` on this backend is a
**deliberate no-op**. The natural implementation, `networksetup
-setairportpower en0 off`, would kill the machine's internet — including the
connection the session is running over. A test backend must never sabotage the
host it runs on, so it refuses to act instead of being helpful.

**Transferable lesson.** Three, and the last is the one worth keeping.

Probe the platform; do not trust documentation about it. Ten minutes of running
four commands beat any amount of reading, and produced a finding (SSID redaction)
that no amount of reading would have surfaced.

A tool that returns *wrong* data is far more dangerous than one that returns
nothing. `airport` failing loudly cost me a minute. `networksetup` answering
confidently and incorrectly would have cost an afternoon, spent debugging the
wrong layer.

And when the platform genuinely withholds something, **propagate the gap instead
of papering over it.** This backend advertises 2 capabilities where the simulator
advertises 8, so tests needing fault injection are skipped with a stated reason
rather than silently passing. A test suite's most valuable property is that a
green run means something; anything that inflates green at the cost of truth is
working against the entire point of the exercise.

---

## #7 — The logs were empty, and the code that wrote them was correct

**Symptom.** Five tests failed. Two of them looked like this:

```
assert 'reason=8' in ''
E   AssertionError
```

An empty string where a log file should have been. The simulator was demonstrably
writing logs — running it standalone produced a perfectly good 3KB file.

**What I first assumed.** A path bug. The Python side computes the log path and
passes it to the simulator over the control protocol, so my first suspicion was
that the two sides disagreed about the filename, or that the artifact directory
was being cleaned up before the read.

**What was actually wrong.** The path was right, the file existed, and it was
**zero bytes** — but only while the simulator was alive:

```
log file exists           : True
size WHILE process alive  : 0 bytes
lines via dut.logs()      : 0
size AFTER close          : 3381 bytes
lines after close         : 29
```

`std::ofstream` buffers in userspace. Nothing reaches the filesystem until the
buffer fills or the stream is destroyed. The C++ logger was correct in isolation;
what was wrong was an **assumption crossing a process boundary** — Python read the
file while C++ still held the bytes in memory.

The reason this survived 93 green C++ unit tests is worth noting. Those tests
assert on `Logger::records()`, the in-memory vector, because that is the fast and
obvious thing to assert on. They never read the file back off disk. The buffering
bug lived precisely in the gap the unit tests did not cover, and only appeared
once a *second process* became the reader.

`PcapWriter` had the identical bug via `FILE*` buffering. It had not surfaced yet
only because nothing had tried to analyse a capture mid-session — it would have
bitten later, during the forensics work, and been much harder to attribute.

**The fix.** Flush after every record, in both writers:

```cpp
file_ << line << '\n';
file_.flush();      // Logger
...
std::fflush(fp_);   // PcapWriter
```

The throughput cost is real and irrelevant: a session writes tens of lines, not
millions. For diagnostics, durability beats throughput. Flushing per frame also
means a *crashed* simulator leaves a valid partial capture rather than an empty
file — which is exactly the run you most want a capture from.

**Transferable lesson.** Buffering is invisible until a second reader appears, and
then it looks like a logic bug in whichever component you happen to distrust more.

More usefully: **unit tests that assert on in-memory state do not test I/O.**
`Logger::records()` and the file on disk are two different outputs, and 93 passing
tests covered only the first. When a component's real contract is "another process
can read this", the test has to cross that boundary too — which is precisely the
distinction between a unit test and an integration test, met here in the wild
rather than in a definition.

---

## #8 — The test suite found a real bug in the device, which is the entire point

**Symptom.** The interop matrix went green except for ten cases, all shaped like
these:

```
FAILED test_invalid_combinations_are_refused[5GHz-80-wpa2_psk-11n-802.11n supports at most 40MHz]
FAILED test_invalid_combinations_are_refused[6GHz-320-wpa3_sae-11ax-320MHz requires 802.11be]
```

**What I first assumed.** That my *test* was wrong. The tests were newly written
and the DUT had 93 passing unit tests behind it, so the prior was that the new
code was the broken code. My instinct was to relax the assertions.

**What was actually wrong.** The tests were right and the DUT was incomplete.

`tests/interop/test_matrix.py` encodes the 802.11 rules independently, in
`is_valid_combination()`. Those rules say a station cannot negotiate 80 MHz on
802.11n (HT caps at 40) and cannot negotiate 320 MHz on 802.11ax (320 MHz arrived
with 802.11be/EHT). The simulator validated band-vs-security and band-vs-PHY, but
**never PHY-vs-width** — so it cheerfully "connected" at 320 MHz on Wi-Fi 6.

That is a worse bug than a failure to connect. A DUT that succeeds at something
the spec forbids is silently wrong, and every downstream layer inherits the error:
the rate model produces impossible throughput numbers, the KPI baselines encode
them as normal, and the ML layer learns that impossible configurations are healthy.

**The fix.** `max_width_for_phy()` / `phy_supports_width()` in the C++ domain
rules, enforced in `connect()` before any frame is transmitted, plus gtest
coverage so the rule is now pinned from both sides.

**Transferable lesson.** Two things, and the second is the one I would actually
say out loud in an interview.

When an independently-written check disagrees with the implementation, that is a
**signal, not noise** — and the direction of the disagreement is information. My
Python matrix and my C++ state machine were written hours apart from the same
spec, and the disagreement located a genuine gap precisely because they were
written independently. Had I derived the test's rules *from* the DUT's rules — the
tempting shortcut, and the one that makes tests pass faster — the test would have
agreed with the bug and I would have shipped it.

And the honest part: **my first instinct was to weaken the test.** That instinct is
always available and always wrong to act on before investigating, because it
converts a found bug into a hidden one. Ten red cases that turn out to be a real
defect are the best possible outcome for a test suite. Recognising that in the
moment — rather than reaching for the assertion and lowering it — is most of what
separates a useful suite from a decorative one.

---

## #9 — The test was right, the DUT was right, and the *model* was wrong

**Symptom.** One performance test failed on the simulator while passing on real
hardware — the opposite of the usual direction:

```
tests/performance/test_link.py::test_channel_and_band_are_consistent
    scan = dut.scan()
DUTError: illegal state transition: illegal transition: CONNECTED --SCAN_START-->
```

**What I first assumed.** That the test was badly written. Calling `scan()` in the
middle of a connectivity test does look careless, and the easy fix was to reorder
the test so it scanned before connecting.

**What was actually wrong.** The transition table encoded a false belief about
802.11. It allowed `SCAN_START` only from `IDLE`, which implicitly asserts that a
station must disconnect in order to scan.

Real stations do not work that way. A **background (off-channel) scan** is how
roaming decisions get made: the radio briefly leaves its operating channel,
samples neighbouring BSSes, and returns — without ever leaving the association.
Every roaming-capable client does this continuously.

So the DUT was refusing a legal operation, and the test was right to ask for it.
Had I "fixed" the test, the rig would have been permanently unable to express a
whole class of real behaviour — including "the link survived a background scan",
which is a genuine regression test for a genuine bug.

Modelling it took some care. The obvious fix, adding `CONNECTED --SCAN_START-->
SCANNING`, is wrong too: `SCANNING --SCAN_DONE--> IDLE` would then drop the
association, so a correctly-behaving scan would report a dropped link. The
association state genuinely does not change during a background scan, so the
correct model is that **no transition occurs at all** — the scan is an operation,
not a state.

```cpp
const bool background = (state_ == State::Connected);
if (background) {
    log(..., "background scan ... assoc_retained=1");
} else {
    transition(Event::ScanStart);
}
```

The two cases are also logged differently (`background scan` vs `scan request`),
so a capture or log can be read afterwards to tell which occurred.

**Transferable lesson.** When a test and an implementation disagree, there is a
third possibility beyond "the test is wrong" and "the code is wrong": **the shared
model is wrong.** Both sides were internally consistent; the domain was
misunderstood. Those are the most valuable failures to chase, because the bug is
in the thinking rather than in the typing, and no amount of code review of either
file would have surfaced it.

Practically: a state machine should model *states* — conditions the system is in —
and resist the pull to model every *operation* as a state. "Scanning" felt like a
state because it takes time, but the station's condition during a background scan
is still "associated". Confusing an activity with a state is how state machines
acquire transitions that do not exist in the real system.

---

## #10 — A real-hardware run took 65 seconds for 14 tests

**Symptom.** `pytest tests/performance --dut=macos` took **65 seconds** for 14
tests. The same suite against the simulator took 0.8 seconds.

**What I first assumed.** That real hardware is simply slow, and this is the price
of testing against it. Partly true, and a comfortable excuse for not looking.

**What was actually wrong.** `system_profiler` costs 2–5 seconds per invocation,
and the suite was calling it roughly forty times. The `MacOSDUT` cache was
**per-instance**, while the `dut` fixture is **function-scoped** — so every test
built a fresh DUT with a fresh, empty cache. The cache existed and cached nothing.

The tempting fix is to widen the fixture to session scope. That would work and it
would be wrong: a session-scoped mutable DUT makes tests order-dependent, which is
the single most confusing class of test bug (each test passes alone; the suite
fails; the failure moves when you add an unrelated test). Trading correctness for
speed in *test infrastructure* is a bad trade, because the infrastructure's only
job is to be trustworthy.

**The fix.** Move the cache from the instance to the class:

```python
_shared_cache: dict[str, dict[str, Any]] = {}
_shared_cache_at: dict[str, float] = {}
```

This is not a cheat, and the justification is what matters: **there is exactly one
Wi-Fi radio in the machine.** Its state is genuinely global, so two DUT objects
observing `en0` *should* see the same answer — a per-instance cache was modelling
a separation that does not exist. Fixture isolation is preserved (each test still
gets its own DUT object, its own artifact directory, its own teardown), while the
expensive read is shared. 65s → 35s, with a 3-second TTL so RSSI still moves
between tests.

**Transferable lesson.** Before optimising, find out **what** is slow. "Real
hardware is slow" was a plausible story that would have stopped the investigation
one step short of a 2× win.

And when caching, put the cache at the scope of the **thing being cached**, not at
the scope of the object that happens to be asking. The radio is process-wide, so
its cache is process-wide. Getting that boundary right is also what let me keep
function-scoped isolation — the speed and the correctness were not actually in
conflict, which is usually the case once the real cause is known.

---

## #11 — The forensics engine called every successful session a failure

**Symptom.** The association analyser was run over all fifteen captures. The
genuine faults were diagnosed beautifully — M3 timeout distinguished from PMK
mismatch by reason code, auth timeout, association status 17. And then:

```
FAIL f_NONE.pcap     link established, then torn down with reason 3 (...STA is leaving)
FAIL s_wpa2.pcap     link established, then torn down with reason 3 (...STA is leaving)
FAIL s_wpa3.pcap     link established, then torn down with reason 3 (...STA is leaving)
```

Every *healthy* capture was reported as a failure.

**What I first assumed.** That the simulator was emitting a spurious deauth at the
end of a session.

**What was actually wrong.** The simulator was right and the analyser was naive.
Reason code 3 is *"Deauthenticated because sending STA is leaving"* — it is the
**normal, correct end of a session**. My rule said "reached a keyed state, then saw
a deauth ⇒ failure", which treats every clean shutdown as a defect.

The deeper error is that I had been reasoning about reason codes as though they
were error codes. They are not: a reason code says *why the association ended*, and
"because I asked it to" is one of the answers. Codes 3 and 8 mean intentional
teardown; 15, 23 and 34 mean something broke.

Direction matters too. A reason-3 deauth **from the station** is unambiguously the
client leaving. The same code **from the AP** is also routine (the AP deassociating
a client deliberately), provided the session had already reached a keyed state — so
the fix checks both the code and the transmitter.

**The fix.** A named `GRACEFUL_REASONS = {3, 8}` set, plus a direction check, and a
distinct success verdict for a clean close. Sessions that ended intentionally now
report success while still surfacing any quality problems observed along the way
(retry rate, weak signal) as evidence rather than as failures.

**Transferable lesson.** Before writing rules over a coded protocol field,
establish which values mean "broken" and which mean "finished". I had read the
reason-code table as a list of errors because it appears in failure paths, and that
framing quietly produced a detector that could never report a healthy session.

Worth noting what caught this: running the analyser over the **whole corpus**,
including the cases expected to pass. Had I only ever tested it against captures of
known faults, the false positive on healthy traffic would have been invisible —
every capture I looked at *was* a failure, so "reports failure" always looked
right. Negative and positive cases both, always.

---

## #12 — My C++ built EAPOL correctly and my Scapy helper did not

**Symptom.** A synthetic KRACK (key-reinstallation) capture was produced to test a
detector, and the detector found nothing. The dissector reported nine frames: one
beacon and eight generic `data` frames. No EAPOL at all.

**What I first assumed.** A bug in the new detector — it was the newest code, and
the frames were "obviously" being generated correctly because I had written the
EAPOL key body by hand and could see the bytes.

**What was actually wrong.** `tshark` again, and again it was right:

```
2   I P, N(R)=47, N(S)=0; DSAP LLC Sub-Layer Management Individual, ...
```

The frames were missing their **LLC/SNAP header**. An 802.11 data frame carrying
EAPOL must announce EtherType `0x888E` via LLC/SNAP (`AA AA 03 00 00 00 88 8E`);
without it a dissector has no way to know the payload is 802.1X, so it falls back to
raw LLC. Stacking `Dot11 / EAPOL` in Scapy serialises happily and produces a frame
that no standard tool can interpret.

The part I find genuinely instructive: **my C++ frame builder gets this right.**
`sim/src/frame.cpp` inserts the SNAP header explicitly, which is why the
simulator's own captures decode as "Key (Message 1 of 4)" in Wireshark. I wrote the
correct version hours earlier, then wrote the incorrect version in a different
language and did not notice, because Scapy's fluent `/` syntax reads as though it
handles encapsulation for you. It does not — it stacks exactly what you name.

**The fix.** `Dot11 / LLC(...) / SNAP(code=0x888E) / EAPOL(...)`. Verified against
tshark, which now labels all five M3s. The detector fires with its full
explanation, including the increasing replay counters that distinguish a deliberate
replay from ordinary retransmission.

While fixing this I also hit a second version-drift trap in the same file: Scapy
2.7 renamed the `Dot11` FCfield flags from `"to-DS"`/`"from-DS"` to
`"to_DS"`/`"from_DS"`, and passing the old spelling raises `ValueError` at
construction. Rather than hardcode either spelling, the code now asks Scapy for its
own field names and picks whichever exists — the library knows, so there is no
reason to guess:

```python
_TO_DS = _fc_flag("to_DS", "to-DS")
```

**Transferable lesson.** Getting something right once does not transfer across
languages or libraries — the knowledge lives in the code, not in your head, and a
different API will happily let you omit what the other one forced you to state.

And the recurring theme, now for the third time in this journal (#5, #8, #12):
**the independent oracle found the bug.** `tshark` has now caught a malformed SAE
frame, a missing SNAP header, and would have caught more. A dissector validated
only against captures your own code produced is validated against nothing — the
two share every assumption, including the wrong ones. Which is precisely why
`pcap/tshark_check.py` exists as a first-class part of this project rather than a
debugging convenience.

---

## #13 — The DUT's own statistics contradicted its own packet capture

**Symptom.** One test in the packet layer failed:

```
test_channel_busy_raises_excessive_retries
  assert found, f"retry rate was {cap.retry_rate:.1%}, expected an anomaly"
```

The DUT had been told to simulate a congested channel. Its API reported a 34.8%
retry rate. Its capture, of the same session, contained **zero** frames with the
Retry bit set.

**What I first assumed.** A dissector bug — that I was reading the Retry bit from
the wrong offset in Frame Control. That is a genuinely easy mistake and it was the
obvious suspect, since the dissector was the newer code.

**What was actually wrong.** The dissector was reading the bit correctly. The bit
was never set, because `FrameBuilder::data_frame()` **had no retry parameter at
all.** The simulator's traffic loop did this:

```cpp
const bool retry = rng_.bernoulli(busy ? 0.34 : 0.02);
if (retry) ++tx_retries_;                       // counter incremented
emit(FrameBuilder::data_frame(..., seq_++, ...),  // frame built WITHOUT the flag
     false, retry && rng_.bernoulli(0.1));        // `retry` only reached bad_fcs
```

The counter went up and the frame went out unchanged. The `retry` variable was
used for the FCS decision and silently dropped on the floor for the frame itself.

This is the worst class of bug in a test rig, and it is worth being precise about
why. A rig that *fails* is annoying; a rig whose **self-reported metrics disagree
with its own observable output** is corrosive, because every consumer downstream
picks one of the two numbers and inherits the discrepancy. The KPI baselines would
have recorded 34% as normal; the ML layer would have trained on a feature that does
not exist in the captures; the triage agent would have been handed a "retry rate"
it could never corroborate from evidence. Days later, someone would be debugging
the ML layer for a bug that was here.

**The fix.** Two parts, and the second matters more than the first.

Adding a `retry` parameter is the obvious half. The subtler half is that
**a retransmission is not a flag on a frame — it is another frame.** Real 802.11
retransmission puts a second copy on the air carrying the *same sequence number*
with the Retry bit set; that duplicate sequence number is precisely how a receiver
recognises it as a retry rather than as new data. So:

```cpp
const std::uint16_t seq = seq_++;
emit(data_frame(..., seq, ..., /*retry=*/false));          // original
if (will_retry) {
    ++tx_retries_;
    emit(data_frame(..., seq, ..., /*retry=*/true));       // same seq, retry set
}
```

Modelling it as a boolean on one frame would have set the bit and still been wrong,
because retry rate is a *ratio of frames transmitted to frames delivered* — and with
one frame per attempt that ratio is unmeasurable. Verified after the fix:

```
CHANNEL_BUSY   pcap retry_rate= 25.9%   sim reported= 25.8%
NONE           pcap retry_rate=  2.1%   sim reported=  2.1%
```

**Transferable lesson.** When two of your own components disagree about a number,
resist the urge to pick the one you trust more and move on — one of them is wrong,
and knowing which is the whole finding. The two numbers here were 34% and 0%, and
either could have been defended in isolation.

More generally: **a counter and the thing it counts are two separate pieces of code
that can drift apart.** `++tx_retries_` compiled fine and was never wrong about
what it was told; it was simply counting an event that was not happening. Whenever
a metric can be incremented independently of the behaviour it describes, that
divergence is worth asserting on directly — which is what
`RetryCounterAgreesWithTheFramesActuallyTransmitted` now does in the gtest suite.

And the meta-observation, now consistent across this whole journal: **every
significant bug was found by a layer above, validating against an independent
source.** The interop matrix found the missing width rule (#8), the performance
tests found the scan-while-connected model error (#9), `tshark` found two malformed
frame bugs (#5, #12), and the packet layer found this one. None of these were found
by the unit tests of the component that contained the bug — because a component's
own tests share its assumptions. That is the argument for integration testing, met
five separate times in one day.

---

## #14 — A 9× throughput collapse passed the regression detector cleanly

**Symptom.** The regression detector was tested against baselines learned from ten
real measurement runs on this machine. Latency regressions were caught correctly.
Then:

```
throughput collapsed   throughput  4.0 -> OK   (baseline 35.88 mbps)
```

Throughput falling from 36 Mbps to 4 Mbps — an 89% drop — reported **OK**.

**What I first assumed.** That my `HIGHER_IS_BETTER` direction logic was inverted,
so a fall in throughput was being scored as an improvement. That would have been a
simple sign error and it was the obvious candidate.

**What was actually wrong.** The direction logic was correct. The z-score was
correct. The *approach* was inadequate, and the numbers say exactly why:

```
cloudflare_edge/throughput  median=35.88  mad=18.42  relative_mad=51%
```

The MAD is **51% of the median**. Throughput over a real consumer connection
genuinely varies that much between measurements — TCP ramp-up, competing traffic,
CDN PoP selection, Wi-Fi airtime contention. So:

```
z = 0.6745 * (4.0 - 35.88) / 18.42 = -1.17
```

An 89% collapse scores **z = -1.2**, nowhere near the 3.5 threshold.

The important realisation is that **this is not a threshold-tuning problem.** A
z-score can only resolve changes larger than the metric's own variance. With 51%
natural variability, any threshold low enough to catch a 2× drop would also fire on
ordinary noise several times a day. There is no value of `Z_WARN` that fixes this,
and spending an hour tuning one would have been an hour spent not understanding the
problem.

Worth noting why this only showed up now: the baseline was built from **real
measurements**. Had I seeded it with synthetic well-behaved data, MAD would have
been small, the z-score would have worked, and I would have shipped a detector that
silently fails on exactly the metric people care most about.

**The fix.** A second, scale-free test running alongside the z-score:

```python
SEVERE_RATIO = 2.5      # this much worse than baseline is a regression, period
CRITICAL_RATIO = 4.0
```

The ratio is normalised so that ">= 1 means worse" regardless of the metric's
direction, and a regression is flagged when **either** test trips. The two tests
cover complementary regimes, which is the actual insight:

* the **z-score** catches small but statistically significant drift on *tight*
  metrics (jitter, with a 23% relative MAD),
* the **ratio test** catches large qualitative changes on *noisy* metrics
  (throughput, DNS, both at 51%).

Baselines also now report `relative_mad` and an `is_noisy` flag, and the verdict
prints `[noisy baseline]` so nobody reads more precision into a number than it
carries. After the fix:

```
3x slower    12.0 -> WARNING   z=-0.9  regression (3.0x worse than baseline) [noisy baseline]
9x slower     4.0 -> CRITICAL  z=-1.2  CRITICAL regression (9.0x worse than baseline)
5x faster   180.0 -> IMPROVED  z=+5.3
```

**Transferable lesson.** Before trusting any statistical test, **measure the
variance of the thing you are testing.** `relative_mad` is now reported for every
baseline precisely because it determines whether a z-score is a usable instrument
for that metric at all. A test that cannot resolve the effect size you care about
is not a conservative test — it is a test that returns "fine" no matter what
happens, which is worse than having none, because it carries authority.

And the more general version: **a detector needs to be evaluated against the
magnitude of change it is supposed to catch**, not merely against "does it flag the
obviously broken case". I had two examples that worked (latency) and concluded the
detector worked. The third case was not an edge case; it was the most important
metric in the suite.

---

## #15 — The clustering was right; two things upstream of it were wrong

**Symptom.** Failure clustering over 180 labelled runs produced 10 clusters, nine of
them perfectly pure. The tenth:

```
cluster 6 (42 runs, purity 43%, dominant=LOW_RSSI)
```

It had merged four different injected faults into one group.

**What I first assumed.** That `eps` needed tuning, or that TF-IDF was the wrong
representation. Both are the kind of knob you can turn for an hour and feel
productive.

**What was actually wrong.** Neither. Printing the signatures of the merged members
showed the clustering was behaving correctly — the runs genuinely looked identical —
and revealed **two separate upstream bugs plus one representation flaw**:

```
LOW_RSSI    : signal below usable threshold ... closed cleanly (reason 3 ...)
DEAUTH      : deauth received reason=3 reason_name=DEAUTH_LEAVING ... closed cleanly
M3_TIMEOUT  : (open network) ... connection completed successfully ... closed cleanly
PMK_MISMATCH: (open network) ... connection completed successfully ... closed cleanly
```

**Bug one: the injected `DEAUTH` fault reported reason code 3.** Code 3 is
`DEAUTH_LEAVING`, *"deauthenticated because the sending STA is leaving"* — which is
precisely what the simulator sends during a **normal, graceful disconnect**. So an
injected deauth fault was byte-for-byte indistinguishable from a clean shutdown. Not
a clustering failure at all: two things that look identical *are* identical as far as
any downstream layer can tell. Fixed by defaulting the fault to reason 1
(`Unspecified`), still overridable via `--code`.

Note the irony: journal entry #11 was about teaching the forensics layer that reason
3 means "intentional". Having taught it that, I then injected a fault that used
reason 3 — so the analyser correctly classified my deliberate fault as intentional.
The two bugs were the same misunderstanding viewed from opposite ends.

**Bug two: `open_FOURWAY_M3_TIMEOUT` and `open_PMK_MISMATCH` were labelled as
failures, and they succeeded.** An open network has no 4-way handshake, so a
handshake fault has no stage to fire in. The simulator was entirely correct to
connect successfully. The bug was in the **corpus builder**, which generated every
(scenario, fault) pair without asking whether the pair was meaningful, then labelled
the result as "fault injected".

This is the worst of the three, because it is a **poisoned label**. Those six runs
told every downstream evaluation that a successful connection is what a handshake
failure looks like. Fixed with an explicit `INAPPLICABLE` map and an `is_applicable()`
check.

**Representation flaw.** LOW_RSSI genuinely connects and merely degrades, so its
signature legitimately shares most of its text with a healthy run. Two changes fixed
it: truncate the forensics verdict to its first clause (120 characters of shared
prose was drowning the discriminative tokens under char-n-gram similarity), and add
explicit `degraded_weak_signal` / `degraded_high_retry` / `degraded_rssi_collapse`
tokens so a difference that lived only in a numeric field becomes visible to a text
clusterer.

**Result.** 174 failures → 10 clusters, homogeneity 1.00, completeness 1.00, ARI 1.00.

**On that perfect score — the honest caveat.** ARI 1.00 is not evidence that this
clustering approach is excellent. It reflects that the data is unusually clean: a
deterministic simulator, ten faults engineered to be distinguishable, and each one
emitting a distinctive log line. Real production failures overlap, co-occur, and
arrive with missing artifacts; a realistic ARI there would be 0.5–0.7 and the honest
answer would involve a human reviewing cluster exemplars. What the perfect score does
demonstrate is that the *pipeline* is sound — features, distance metric and evaluation
are wired up correctly — which is exactly what a clean-room dataset is for.

**Transferable lesson.** When a model underperforms, **look at the data before
touching the model.** Every instinct here pointed at hyperparameters, and the actual
causes were a wrong constant in C++, a missing precondition in a data generator, and
one over-long text field. An hour of `eps` tuning would have improved the number
slightly and left all three bugs in place.

The label bug deserves its own emphasis: **a mislabelled example is worse than a
missing one.** Six poisoned rows out of 180 were enough to drag a cluster's purity to
43%, and no amount of modelling can recover from being told the wrong answer.

---

## #16 — My classifier reported perfect precision, and I do not believe it

**Symptom.** Nothing failed. The flake classifier reported:

```
flake classifier: precision=1.00 recall=1.00 f1=1.00 (trained on 46, tested on 21)
```

**Why I went looking anyway.** A perfect score on a first attempt is a smell, not a
success. The classification report showed why:

```
              precision    recall  f1-score   support
      stable       1.00      1.00      1.00        20
       flaky       1.00      1.00      1.00         1
```

**Support: 1.** The held-out set contained exactly **one** flaky example. With one
positive sample, precision and recall are each either 0.0 or 1.0 — there is no other
possible value. The metric is not "excellent", it is *uninformative*, and it was
reported with two decimal places of false authority.

Feature importance made the second problem plain:

```
transition_rate 0.220   runs 0.210   transitions 0.200
longest_streak  0.190   flake_rate 0.180   pass_rate 0.000
```

Importance is spread almost evenly, which on a dataset this small means the model is
fitting noise — with 46 training rows a RandomForest will find *something* in any
feature. And the statistical method immediately above it in the same output achieves
the identical result with no model, no training, and complete explainability:

```
statistical detection (flake_rate threshold):
  true positives=3  false positives=0  false negatives=0   precision=1.00 recall=1.00
```

**The fix — and it is not a modelling change.** The code now refuses to let me quote
the number:

```python
MIN_TEST_POSITIVES = 5
...
if not self.metrics_are_trustworthy:
    line += ("WARNING: only N flaky example(s) in the held-out set ... "
             "These metrics are NOT meaningful ...")
```

and the CLI states outright that for this problem the simple threshold is the better
engineering answer, with the classifier retained to demonstrate the method and to
make the comparison explicit.

**Transferable lesson.** Read the **support column**, always. A 1.00 next to
`support: 1` is not a result. This is the single easiest way to oversell an ML
result, and it is usually done in good faith — the number is real, the computation is
correct, and the conclusion is still unsupported.

The bigger point: **a baseline you can explain beats a model you cannot, and you only
know which you have if you build both.** The flake rate is exact, needs no training
data, and a human can verify it by looking at a pass/fail string. Choosing it over a
RandomForest is not an admission that the ML did not work — it is the entire purpose
of having a baseline. What would have been genuinely wrong is shipping the classifier
*because* it is more impressive, and I would rather be able to explain that trade-off
in an interview than claim a 1.00 I cannot defend.

---

## #17 — The MCP SDK had moved a major version under me

**Symptom.** The MCP server would not start:

```
AttributeError: 'Server' object has no attribute 'list_tools'
```

**What I first assumed.** A typo in the decorator name, or an import from the wrong
submodule.

**What was actually wrong.** I had written the server against the **MCP Python SDK
1.x** API, which I knew from memory:

```python
server = Server("airframe")

@server.list_tools()
async def list_tools() -> list[Tool]: ...
```

`pip` had installed **2.2.0**. The SDK's own error message was unusually helpful
about it:

> No module named 'mcp.server.fastmcp'. This is mcp 2.x, where FastMCP was renamed to
> MCPServer (from mcp.server.mcpserver import MCPServer) and other APIs changed

Three things changed, and only the first is cosmetic:

1. `FastMCP` → `MCPServer`.
2. **Tool schemas are derived from type hints** rather than hand-written JSON Schema.
   `server.add_tool(fn, name=..., description=...)` introspects the signature.
3. The wire model moved from camelCase to **snake_case** (`serverInfo` →
   `server_info`, `inputSchema` → `input_schema`), which bit my *test client* twice
   after the server was already working.

Point 2 turned out to be a genuine improvement to the design, not just a migration
cost. Under 1.x the JSON Schema was written out by hand next to each tool, which is
duplication waiting to drift: change a parameter and the schema silently lies to the
model. Under 2.x the schema comes from the function signature, so it cannot drift —
verified by asking the server what it advertises:

```
schema auto-derived from type hints (analyze_pcap):
  properties: ['tag', 'detail']
  required  : ['tag']
```

That `required: ['tag']` was inferred purely from `tag` having no default value.

**The fix.** Rewrite `build_server()` against 2.x, registering the same plain
functions the CLI already used — so there is exactly one implementation of each tool
and no possibility of the MCP path and the CLI path diverging. Verified over the real
stdio protocol with an actual MCP client: initialize, list 14 tools, then
`analyze_pcap` and `triage_failure` returning correct results.

**Transferable lesson.** This is the same lesson as journal entry #3 (pytest 8 → 9),
which is itself the point: **it happened twice in one day, on two different
dependencies, for the same reason.** Both times I wrote code from memory of an API,
and both times the installed major version had moved. Writing `>=` in a dependency
spec and then coding against whichever version you last used is a habit that
generates this class of bug indefinitely.

The habit that actually fixes it is boring: **check the installed version and read its
real API before writing against it.** `dir()`, `inspect.signature()` and the package's
own error messages resolved this in about three minutes, against however long I would
have spent guessing at decorator names.

And credit where it is due — a library whose `ImportError` tells you the new class
name, links the migration guide, *and* names the pin that would restore the old
behaviour is doing error messages properly. It turned a confusing failure into a
three-minute fix, which is a standard worth copying in my own error messages.

---

## #18 — `--retries=2` reported "no tests ran"

**Symptom.** The retry mechanism, which is the plugin's headline feature:

```
$ pytest tests/connectivity -q --retries=2
no tests ran in 0.20s
```

42 tests collected, zero reported.

**What I first assumed.** That returning `True` from `pytest_runtest_protocol` was
suppressing the report — that I had claimed responsibility for the item and then not
fulfilled the contract.

**What was actually wrong.** Half right, and the wrong half was the interesting one.
`runtestprotocol()` takes a `log` parameter controlling whether the resulting reports
are emitted to pytest's reporting hooks. My loop said:

```python
reports = runtestprotocol(item, nextitem=nextitem, log=(attempt == retries))
```

With `retries=2` that logs only on attempt index 2 — the last one. But a test that
**passes on the first attempt breaks out of the loop immediately**, before any attempt
with `log=True` ever runs. So every passing test was executed and then silently
discarded.

The flaw is a sequencing one: I was deciding *whether to report* an attempt before
knowing whether that attempt would be the one accepted. The two are not independent —
the accepted attempt is by definition the one that must be reported, and which one
that is cannot be known until it has run.

**The fix.** Run every attempt with `log=False`, decide which one to accept, then emit
that attempt's reports explicitly:

```python
reports = runtestprotocol(item, nextitem=nextitem, log=False)
call_report = next((r for r in reports if r.when == "call"), None)
accepted = call_report is None or not call_report.failed or is_last
if not accepted:
    continue
...
for report in reports:
    item.ihook.pytest_runtest_logreport(report=report)
```

While in there I also attached a section to the accepted report
(`"passed on attempt 2 of 3 — recorded as a FLAKE"`), so a green test that only went
green on a retry says so in its own output rather than only in the summary.

**Transferable lesson.** This is a bug I created by writing the loop in the order I
*thought* about it (run, maybe log, maybe continue) rather than in the order the data
requires (run, decide, then report). Whenever a loop both accumulates results and
decides which one counts, the reporting has to happen after the decision — and a
condition written in terms of the loop index (`attempt == retries`) is a warning sign,
because it encodes an assumption about which iteration will be last.

There is a pointed irony worth keeping: **the feature was a flake-detection mechanism,
and its own bug was that it hid results.** The thing I built to stop a test framework
from lying was, for about an hour, the thing lying.

---

## #19 — Every bug I fixed today showed up in the flake leaderboard

**Symptom.** With real run history accumulated, the flake report looked wrong:

```
failing rate=0.33 runs=3 transitions=1  F..  test_invalid_combinations_are_refused[...]
failing rate=0.50 runs=2 transitions=1  F.   test_channel_busy_raises_excessive_retries
```

Sixteen tests flagged as problematic. But those are precisely the tests that caught
the PHY-width bug (#8) and the retry-bit bug (#13) — they failed, I fixed the DUT, and
they have passed ever since. They are the **successes** of the day, listed as
liabilities.

**What I first assumed.** That the `FLAKE_THRESHOLD` was too low and needed raising.

**What was actually wrong.** The threshold was irrelevant. `flake_rate` measures
*inconsistency*, and inconsistency is not the same thing as flakiness. Four
qualitatively different histories all produce a nonzero rate:

| pattern | flake_rate | transitions | what it actually is |
| --- | --- | --- | --- |
| `FFFF....` | 0.50 | 1 | somebody **fixed** it |
| `....FFFF` | 0.50 | 1 | somebody **broke** it — urgent |
| `.F.F.F.F` | 0.50 | 7 | genuinely **flaky** |
| `FFFFFFFF` | 0.00 | 0 | consistently **failing** |

Rows one and three have identical flake rates and call for opposite responses: one
needs nothing done at all, the other needs the test rewritten. And row two — a
regression — is the most urgent of the four and would have been buried in the same
undifferentiated list.

The discriminator was already in the code and unused. `transitions` counts how often
the outcome flipped: **one transition is a step change; many transitions is a flake.**
I had written the feature, documented why it mattered, fed it to the classifier, and
then not used it in the actual verdict.

**The fix.** `is_flaky` now requires `transitions >= 2`, and a `classification`
property returns one of `stable | failing | fixed | regressed | flaky`. The MCP tool
groups by it, with the action for each spelled out:

```
FLAKY (1)      <- fix the TEST: alternates between pass and fail
REGRESSED (0)  <- URGENT: was passing, now fails
FIXED (16)     <- was failing, now passes (not a flake)
STABLE (303)
```

**Transferable lesson.** A single scalar rarely separates categories that demand
different actions. `flake_rate` is a perfectly good measure of *inconsistency* and a
bad classifier of *flakiness*, and the gap between those two is where the bug lived.
Before ranking anything by a metric, enumerate the distinct situations that produce
the same value — if they call for different responses, one number is not enough.

The other half is more uncomfortable: **the feature I needed was already implemented.**
`transitions` existed, with a docstring explaining exactly this distinction, and the
verdict simply did not consult it. Writing the right abstraction is not the same as
using it, and a helper with a good docstring is easy to mistake for a solved problem.
