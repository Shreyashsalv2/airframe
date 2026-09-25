# Architecture

Every significant decision in airframe, the alternative that was rejected, and what
the trade cost. Where a decision was later proved right or wrong by a bug, the
`BUILD_JOURNAL.md` entry is cited.

---

## 1. One test suite, many backends

**Decision.** Tests are written against an abstract `DUT` protocol
(`src/airframe/dut/base.py`). Two backends implement it: a deterministic C++ simulator
and this MacBook's real Wi-Fi interface. The suite selects one with `--dut=sim` or
`--dut=macos` and the test bodies never branch on which.

**The alternative.** Two parallel suites, one for simulation and one for hardware.

**Why that loses.** The two drift. The expensive one — real hardware — is always the
less-maintained one, so the suite you trust least is the one closest to production.
Adding a third backend (a router over SSH, an Android phone over ADB) means a third
rewrite rather than a third file.

**What it costs.** A real constraint on the interface: it can only express operations
that make sense for every backend, and the awkward cases have to be handled explicitly
rather than ignored. That is the capability problem, below.

---

## 2. Capabilities are declared, and unavailable tests skip with a reason

**Decision.** Each backend advertises a `frozenset[Capability]`. Tests declare
requirements with `@pytest.mark.requires_capability(...)` and the plugin skips them at
**collection time**, naming the backend in the reason. The simulator advertises 8
capabilities; real hardware advertises 2.

**The alternatives, and what each costs.**

| Approach | Cost |
| --- | --- |
| Lowest common denominator — expose only what every backend supports | Throws away the simulator's entire value. Fault injection is the point of having one. |
| Pretend, and let unsupported calls fail | A test that dies with `AttributeError` tells you nothing about coverage. Failures and gaps become indistinguishable. |
| **Declare, and skip with a reason** | Requires maintaining the capability set honestly. In exchange, `224 skipped` on real hardware is a *map of what the rig cannot do*, not noise. |

**Why this matters more than it looks.** A test suite's single most valuable property
is that green means something. Anything that inflates green at the cost of truth works
against the entire point. A skip that says `backend 'macos' lacks capability
'fault_injection'` is honest, greppable, and shows up in the report as a known gap.

Checking at collection rather than inside the test body is deliberate: a test that
discovers mid-body that it cannot run has already touched the DUT.

---

## 3. Virtual time in the simulator

**Decision.** The simulator never sleeps. Every delay advances a `VirtualClock`
counter. A connection that "takes" 2.4 seconds completes in microseconds, while the
emitted logs and pcap carry realistic millisecond timings.

**The alternative.** Real `sleep()` calls, so the simulation runs at wall-clock speed.

**Why that loses, twice.** It is slow — the 542-test suite would take hours instead of
37 seconds. And it is *flaky*, because wall-clock timing varies with machine load, so
any assertion about duration becomes a race. Virtual time removes both problems with
one decision.

**The consequence that makes everything else possible.** Because the simulator is fast
*and* deterministic, the `dut` fixture can be **function-scoped** — a fresh DUT per
test, complete isolation, no order dependence. That is normally the expensive choice.
Here it costs a few milliseconds.

---

## 4. The state transition table is data, not control flow

**Decision.** Legal transitions live in a `map<pair<State, Event>, State>`
(`sim/src/state_machine.cpp`). An illegal transition throws `IllegalTransition`
carrying both halves of the pair.

**The alternative.** Nested `if`/`switch` inside each state handler.

**What the data form buys.** The table can be tested as a pure function without
constructing a simulator — `tests/test_state_machine.cpp` exhaustively enumerates every
`(state, event)` pair, proves every state is reachable from `IDLE` by breadth-first
search, and proves no state is a trap. None of that is possible against control flow
scattered through handlers.

Throwing rather than silently ignoring an illegal transition matters because the caller
is the thing under test: a bug in the driver surfaces immediately instead of leaving
the DUT quietly in a wrong state.

**Where the model was wrong.** The table initially allowed `SCAN_START` only from
`IDLE`, which implicitly asserts that a station must disconnect to scan. Real stations
perform background off-channel scans while associated — that is how roaming works. The
fix was *not* to add a transition: the association state genuinely does not change, so
a background scan is an operation, not a state (journal #9).

---

## 5. Robust statistics everywhere network data is involved

**Decision.** Baselines are **median + MAD**, not mean + standard deviation. Alerting
uses the modified z-score. Percentiles are reported directly.

**Why.** Latency is heavy-tailed. A connection producing 20ms samples all day will
occasionally produce a 2000ms sample. Concretely:

```
samples : 20 21 19 22 20 2000  (ms)
mean    : 350.3      mean + 3σ : 2563.6   ← the alert threshold
median  :  20.5      median + 3.5·MAD : 24.0
```

The outlier has raised the alert threshold **above the failure it was meant to catch**.
A subsequent degradation from 20ms to 2500ms would not trip it. Worse, the outlier's
own classic z-score is 2.24 — under the conventional 3.0 cutoff, so the statistic
cannot even flag the value that broke it.

**Where robust statistics were not enough.** A 9× throughput collapse scored z = −1.2
against a baseline with 51% relative MAD and passed cleanly. That is not a tuning
problem: with that much natural variance, no z-threshold separates a 2× change from
noise. The fix was a second, scale-free **ratio test** running alongside — the two
cover complementary regimes, z-scores for tight metrics and ratios for noisy ones — plus
reporting `relative_mad` so nobody reads more precision into a number than it carries
(journal #14).

---

## 6. Rule-based forensics, ML for clustering

**Decision.** The packet forensics engine (`src/airframe/pcap/assoc.py`) is entirely
rule-based. The ML layer is applied only to clustering unknown failure shapes across
many runs.

**Why not ML for forensics.** The 802.11 association sequence is a *specified, finite*
state machine. The rules are known, so encoding them directly gives an answer that is
exact, explainable and auditable. A model would be less accurate, unexplainable, and
would need training data for a problem with a closed-form answer.

**Why ML for clustering.** The opposite situation: the question is "which of these 200
failures are the same bug", the answer is not specified anywhere, and the input is
free-form text. TF-IDF plus DBSCAN is the right tool — and **DBSCAN specifically**,
because it does not require the cluster count up front, which is precisely the unknown.
k-means would force every point into a cluster, so a unique failure corrupts whichever
centroid it lands near.

**The general principle.** Reach for ML where the rules are genuinely unknown, not
where writing them is merely tedious.

---

## 7. Feature engineering is the clustering algorithm

**Decision.** Failure signatures scrub every run-specific value — MACs, IPs,
timestamps, seeds, elapsed times — before clustering, and add explicit tokens for
conditions that live only in numeric fields (`degraded_weak_signal`,
`m2_retransmit_x4`, `missing_m3`).

**Why it is the whole algorithm.** If volatile values survive, every failure is unique
and no clustering method recovers. The DBSCAN call is three lines; the scrubbing is the
part that decides whether it works.

**Proved by a bug.** A cluster came back 43% pure. The cause was not `eps` — it was
three upstream problems: an injected fault reusing reason code 3 (the same code as a
graceful disconnect), six mislabelled corpus rows, and a 120-character verdict string
diluting the discriminative tokens under char-n-gram similarity. An hour of
hyperparameter tuning would have improved the number slightly and left all three in
place (journal #15).

---

## 8. Retries record flakes; they do not hide them

**Decision.** The custom plugin retries failing tests, but stores **every attempt** as
its own row, marks a test that passed only after failing as `is_flake`, and lists
flakes under their own heading in the terminal summary.

**The alternative.** `pytest-rerunfailures`, which reports a test that passed on retry
as simply *passed*.

**Why that loses.** It makes CI green, which is why people install it, and it converts
a real signal — "something here is nondeterministic" — into silence. A suite that hides
flakes accumulates them until nobody trusts a red build, at which point the suite has
stopped working and nobody has noticed.

**The result.** A green build that still tells the truth. "Passed on attempt 3" is a
different and far more actionable fact than "passed", and preserving that difference is
what test infrastructure is *for*.

**The refinement.** `flake_rate` alone conflates four situations that demand opposite
responses — flaky, fixed, regressed and consistently failing all produce a nonzero
rate. The discriminator is `transitions`: one transition is a step change, many is a
flake. Without it, every bug fix in the repository's history appears in the flake
leaderboard (journal #19).

---

## 9. An independent oracle for the packet dissector

**Decision.** The hand-written 802.11 dissector is cross-validated against `tshark` on
every capture in the corpus, and the cross-check `skip`s loudly when `tshark` is absent
rather than passing silently.

**Why.** The dissector, the frame builders and the captures were all written by one
person from one reading of the spec — so they agree with each other *by construction*,
including wherever that reading is wrong. `tshark` is a decades-old independent
implementation; when it disagrees, the prior should be that we are wrong.

**It earned its place three times.** It caught empty SAE frame bodies (journal #5), a
missing LLC/SNAP header on synthetic EAPOL frames (journal #12), and would have caught
the PHY-width gap. In the first case my instinct was to dismiss it — which is the
failure mode worth naming: **an oracle you overrule when it is inconvenient has value
zero.**

---

## 10. The LLM sits behind a provider interface

**Decision.** The triage agent never imports a vendor SDK. `LLMProvider` has three
implementations: `GroqProvider`, `MockProvider` and `AnthropicProvider`. The model is
chosen by querying the provider's live `/models` endpoint, never hardcoded.

**Three reasons, in order of how much they matter.**

1. **Tests must not need a network or a key.** `MockProvider` is deterministic and
   offline, so the entire triage pipeline — loop termination, tool failure handling,
   malformed-output recovery, the evidence guardrail — is covered by assertions. An
   agent that can only be observed by calling a paid API is an agent nobody can test.
2. **Providers change.** Model names get deprecated and rate limits bite. A vendor name
   compiled into agent logic becomes a migration project.
3. It is the honest engineering answer, and it is the sort of decision an interviewer
   pushes on.

`AnthropicProvider` exists specifically to prove the abstraction is real: Anthropic's
API differs in shape (system prompt as a separate parameter, `input_schema` rather than
`parameters`, content as blocks), and adapting all of that behind one `complete()`
signature is what distinguishes an abstraction from an OpenAI wrapper.

---

## 11. Context engineering, not log-dumping

**Decision.** The triage agent receives a **failure bundle** — forensics verdict, mined
log templates, the correlated error window, KPI deltas, cluster membership — inside a
token budget, with the lowest-value sections dropped first. Not the raw log.

**Why.** Cost and latency scale with tokens; signal gets diluted (a model attends worse
to a needle in 4,000 lines than in 40); and dumping raw text asks the model to
re-derive analysis that deterministic code already did correctly. The model's job is
judgement across sources, not string parsing — which it does worse than a regex.

The agent can still drill in: its tools fetch raw logs, specific frame kinds and IEEE
code lookups on demand. Summary by default, detail on request.

---

## 12. Guardrails on the agent's output

**Decision.** Temperature 0. A hard iteration cap. Read-only tools. The verdict must
cite evidence, and confidence is **capped at 0.5 when no evidence is cited**. The
system prompt explicitly permits "insufficient evidence".

**Why each one.**

- *Temperature 0* — the same failure must produce the same verdict, or triage output
  cannot be regression-tested and two engineers reading one bug get different stories.
- *Iteration cap* — a model that keeps requesting the same tool loops until the bill
  arrives.
- *Read-only tools* — an agent whose tools have side effects can make a bad situation
  worse while investigating it.
- *Evidence required* — the main defence against plausible invention. It also makes a
  wrong verdict **checkable** rather than merely wrong.
- *Permitted ignorance* — an agent that always produces a confident root cause is
  producing confident fiction some fraction of the time, and that fraction is invisible
  to the reader.

---

## 13. The MCP server is read-only by default

**Decision.** 14 tools, all inspecting stored artifacts. `run_test` is the sole
exception: gated behind `AIRFRAME_MCP_ALLOW_RUN`, and even when enabled it refuses any
backend but the simulator.

**Why the second gate exists.** Without it, an agent could run `--dut=macos` and drive
the Wi-Fi interface of the machine it is running on — potentially dropping the
connection carrying the session. `MacOSDUT.disconnect()` is a deliberate no-op for the
same reason: the obvious implementation would kill the user's internet. **A test
backend must never sabotage the host it runs on.**

Every tool returns text rather than JSON (models consume text; returning JSON asks the
model to parse and interpret it) and caps its output, because a tool that floods the
context window crowds out the model's own reasoning.

---

## 14. Choices that were deliberately *not* made

**No ORM.** Plain `sqlite3` and hand-written SQL. The schema is the contract between
every layer — the plugin writes it; ML, triage, dashboard and MCP all read it — and
keeping it visible keeps the contract honest.

**No JSON library in C++.** A 200-line hand-written parser instead of nlohmann/json, so
the build has zero third-party dependencies and works offline. In production code this
flips and you take the library; knowing which way the trade points is the skill.

**No `drain3` package.** The template miner is implemented because the algorithm is
~150 readable lines and understanding it is the point. Same trade, stated the same way.

**No dual-axis charts in the dashboard.** Latency and throughput have different scales,
so they get separate panels. Two y-axes on one plot is the single most common charting
mistake and it is always avoidable.

---

## Known limitations

Stated plainly, because a project that claims no limitations is not being honest about
its scope.

- **The simulator is not a radio.** It models the association state machine and the
  frames faithfully, but there is no RF propagation model, no real interference, no
  hidden-node behaviour. Its EAPOL frames are structurally correct but not
  cryptographically valid — computing a real MIC would need the PTK, hence the
  passphrase.
- **`MacOSDUT` observes; it cannot configure.** Joining a specific network
  programmatically needs credentials and CoreWLAN, which is out of scope. It also cannot
  capture packets without monitor mode, and macOS redacts the SSID without Location
  Services permission (journal #6).
- **The clustering result is from clean data.** ARI 1.00 reflects a deterministic
  simulator and ten distinguishable faults, not a claim about production data.
- **The flake classifier is a demonstration, not a recommendation.** The statistical
  `flake_rate` threshold achieves the same result with no model and full
  explainability, and the code says so (journal #16).
- **KPI endpoints are reachable-from-India assumptions.** The Indian ISP resolvers are
  the right targets for the intended context and will behave differently elsewhere.
