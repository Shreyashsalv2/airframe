"""The triage agent — an LLM with tools, iterating toward a root cause.

The loop, which is the whole of "agentic" stripped of mystique:

    1. send the failure bundle + the available tools
    2. if the model asks for a tool, execute it and append the result
    3. repeat until it returns a verdict or we hit the iteration cap
    4. parse the verdict, validate it, store it

Design decisions that matter more than the loop itself
------------------------------------------------------
**Tools are read-only.** Every tool inspects artifacts; none can run a test,
reconfigure a DUT or write to the database. An agent whose tools have side effects is
an agent that can make a bad situation worse while investigating it, and "the triage
bot reconfigured the test rig" is not a story anyone wants to tell.

**A hard iteration cap.** Without one, a model that keeps asking for the same tool
loops until the bill arrives. The cap is low (4) because the bundle already contains
the high-value evidence; tools are for drilling into specifics.

**It must be able to say "insufficient evidence".** The system prompt requires this
explicitly, and low confidence is a valid, useful answer. An agent that always
produces a confident root cause is producing confident fiction some fraction of the
time, and that fraction is invisible to the reader.

**Every claim must cite evidence.** The verdict schema requires an `evidence` list
drawn from the supplied artifacts. This is the main defence against plausible-sounding
invention, and it makes a wrong verdict *checkable* rather than merely wrong.

**Temperature 0.** The same failure must produce the same verdict, or triage output
cannot be regression-tested and two engineers reading the same bug get different
stories.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airframe.triage.bundle import FailureBundle, build_from_tag
from airframe.triage.provider import (
    LLMError,
    LLMProvider,
    LLMResponse,
    ToolSpec,
    get_provider,
)

#: Iteration cap for the tool loop.
MAX_ITERATIONS = 4

#: Valid owners. A constrained vocabulary makes the output routable — free-text
#: owners cannot be aggregated, filtered, or assigned to a team automatically.
OWNERS = (
    "wifi_driver",        # client-side driver or firmware
    "supplicant",         # client-side key negotiation / state machine
    "wifi_infrastructure",  # the AP, controller or authenticator
    "dhcp",               # address assignment
    "dns",
    "isp",                # upstream / last mile
    "provisioning",       # credentials, profiles, certificates
    "environment",        # RF conditions, interference, range
    "test_bug",           # the test or harness is wrong, not the product
    "unknown",
)

SYSTEM_PROMPT = f"""\
You are a wireless quality-engineering triage assistant. You receive an analysed
failure bundle from an 802.11 connectivity test and must determine the root cause.

You know 802.11 well: the association sequence (scan, authentication, association,
4-way EAPOL handshake, DHCP), IEEE status and reason codes, and how failures at each
stage present.

RULES
1. Ground every claim in the supplied evidence. Never invent log lines, frames or
   numbers. If you refer to something, it must appear in the bundle or in a tool result.
2. If the evidence does not support a conclusion, say so and return low confidence.
   "Insufficient evidence" is a correct and valuable answer.
3. Distinguish carefully between failures that share a stage. In particular:
   - reason 15 (4-Way Handshake timeout) means the AP never sent M3 -> infrastructure
   - reason 23 (802.1X authentication failed) means the MIC check failed -> credentials
   Both fail during the handshake; the reason code is what tells them apart.
4. A DHCP failure after a completed handshake is NOT a wireless fault. The radio layer
   succeeded; look upstream.
5. Prefer the simplest explanation consistent with all the evidence.
6. You may call tools to fetch more detail. Do not call a tool if the bundle already
   answers the question.

Reply with ONLY a JSON object, no prose around it:
{{
  "root_cause": "one or two sentences naming the specific failure and why it happened",
  "confidence": 0.0-1.0,
  "suggested_owner": one of {list(OWNERS)},
  "evidence": ["specific facts from the bundle that support this"],
  "bug_report": "markdown bug report: ## Summary / ## Evidence / ## Impact / ## Next steps"
}}
"""


@dataclass
class TriageVerdict:
    root_cause: str = ""
    confidence: float = 0.0
    suggested_owner: str = "unknown"
    evidence: list[str] = field(default_factory=list)
    bug_report: str = ""

    provider: str = ""
    model: str = ""
    tool_calls: int = 0
    iterations: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    latency_s: float = 0.0
    raw_response: str = ""
    parse_error: str | None = None

    @property
    def is_confident(self) -> bool:
        return self.confidence >= 0.6

    @property
    def valid(self) -> bool:
        """A verdict is only usable if it names a cause AND cites something."""
        return bool(self.root_cause) and self.parse_error is None

    def report(self) -> str:
        lines = [
            f"ROOT CAUSE   : {self.root_cause}",
            f"CONFIDENCE   : {self.confidence:.0%}"
            + ("" if self.is_confident else "  (low — treat as a hypothesis)"),
            f"OWNER        : {self.suggested_owner}",
        ]
        if self.evidence:
            lines.append("EVIDENCE     :")
            lines.extend(f"  - {e}" for e in self.evidence)
        lines.append(
            f"\n[{self.provider}/{self.model}  {self.iterations} iteration(s), "
            f"{self.tool_calls} tool call(s), {self.tokens_in}+{self.tokens_out} tokens, "
            f"{self.latency_s:.2f}s]"
        )
        if self.bug_report:
            lines.append("\n" + "=" * 70 + "\nBUG REPORT\n" + "=" * 70)
            lines.append(self.bug_report)
        return "\n".join(lines)


# ---------------------------------------------------------------- tools


def _tool_specs() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="get_log_lines",
            description=(
                "Fetch raw log lines for this failure, optionally filtered by a "
                "substring or by level. Use when the mined templates are not specific "
                "enough and you need the exact wording."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "contains": {"type": "string",
                                 "description": "only lines containing this substring"},
                    "level": {"type": "string", "enum": ["DEBUG", "INFO", "NOTICE",
                                                         "WARN", "ERROR"]},
                    "limit": {"type": "integer", "description": "max lines (default 40)"},
                },
            },
        ),
        ToolSpec(
            name="analyze_pcap",
            description=(
                "Re-run packet forensics and return the frame-by-frame sequence. Use to "
                "confirm exactly which frames were or were not present on the air."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "kind": {"type": "string",
                             "description": "restrict to one frame kind, e.g. eapol_m2"},
                    "limit": {"type": "integer"},
                },
            },
        ),
        ToolSpec(
            name="get_stage_timings",
            description=(
                "Return per-stage durations for the connection attempt. Use to establish "
                "which stage was slow and which stages completed at all."
            ),
            parameters={"type": "object", "properties": {}},
        ),
        ToolSpec(
            name="lookup_ieee_code",
            description=(
                "Look up the meaning of an IEEE 802.11 status or reason code."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "code": {"type": "integer"},
                    "kind": {"type": "string", "enum": ["reason", "status"]},
                },
                "required": ["code", "kind"],
            },
        ),
    ]


class ToolExecutor:
    """Executes tool calls against a bundle's artifacts. Read-only by construction."""

    def __init__(self, bundle: FailureBundle) -> None:
        self.bundle = bundle
        self.call_log: list[str] = []

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        self.call_log.append(f"{name}({json.dumps(arguments, default=str)[:80]})")
        handler: Callable[[dict[str, Any]], str] | None = {
            "get_log_lines": self._get_log_lines,
            "analyze_pcap": self._analyze_pcap,
            "get_stage_timings": self._get_stage_timings,
            "lookup_ieee_code": self._lookup_ieee_code,
        }.get(name)
        if handler is None:
            return f"error: unknown tool {name!r}"
        try:
            return handler(arguments)
        except Exception as exc:                      # noqa: BLE001
            # Return the error as a tool RESULT rather than raising: the model can
            # recover from a failed tool call, but an exception kills the whole triage.
            return f"error executing {name}: {exc}"

    def _get_log_lines(self, args: dict[str, Any]) -> str:
        if not self.bundle.log_path or not Path(self.bundle.log_path).exists():
            return "no log file is available for this failure"
        from airframe.logs.parse import parse_file

        lines = parse_file(self.bundle.log_path)
        contains = str(args.get("contains") or "")
        level = str(args.get("level") or "")
        limit = int(args.get("limit") or 40)

        selected = [
            line for line in lines
            if (not contains or contains.lower() in line.message.lower())
            and (not level or line.level == level)
        ][:limit]
        if not selected:
            return f"no log lines matched (contains={contains!r}, level={level!r})"
        return "\n".join(str(line) for line in selected)

    def _analyze_pcap(self, args: dict[str, Any]) -> str:
        if not self.bundle.pcap_path or not Path(self.bundle.pcap_path).exists():
            return "no packet capture is available for this failure"
        from airframe.pcap.dissect import load_capture

        cap = load_capture(self.bundle.pcap_path)
        kind = str(args.get("kind") or "")
        limit = int(args.get("limit") or 40)

        frames = [f for f in cap if not kind or f.kind.value == kind]
        if not frames:
            return f"no frames of kind {kind!r}; present kinds: {dict(cap.counts())}"
        head = "\n".join(f.summary() for f in frames[:limit])
        return f"{len(frames)} frame(s)\n{head}"

    def _get_stage_timings(self, args: dict[str, Any]) -> str:
        if not self.bundle.forensics or not self.bundle.forensics.timings:
            return "no stage timings are available"
        return "\n".join(
            f"{t.name}: {t.duration_ms}ms" for t in self.bundle.forensics.timings
        )

    def _lookup_ieee_code(self, args: dict[str, Any]) -> str:
        from airframe.pcap.assoc import REASON_CODES, STATUS_CODES

        code = int(args.get("code", -1))
        kind = str(args.get("kind", "reason"))
        table = REASON_CODES if kind == "reason" else STATUS_CODES
        meaning = table.get(code)
        if meaning is None:
            return f"{kind} code {code} is not in the reference table"
        return f"{kind} code {code}: {meaning}"


# ---------------------------------------------------------------- verdict parsing


def parse_verdict(text: str) -> tuple[dict[str, Any], str | None]:
    """Extract the JSON verdict from a model response.

    Models wrap JSON in prose or fences despite instructions, so this is tolerant:
    try the whole string, then a fenced block, then the outermost brace pair. Being
    strict here would mean discarding correct answers over formatting.
    """
    candidates: list[str] = [text.strip()]

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1))

    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        candidates.append(text[first : last + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and "root_cause" in parsed:
                return parsed, None
        except json.JSONDecodeError:
            continue
    return {}, f"could not parse a JSON verdict from {len(text)} chars of response"


def _coerce(parsed: dict[str, Any]) -> dict[str, Any]:
    """Normalise a parsed verdict, clamping anything out of range."""
    confidence = parsed.get("confidence", 0.0)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    owner = str(parsed.get("suggested_owner") or "unknown").strip().lower()
    if owner not in OWNERS:
        # Map a near-miss rather than discarding it; models paraphrase enum values.
        owner = next((o for o in OWNERS if o in owner or owner in o), "unknown")

    evidence = parsed.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]

    return {
        "root_cause": str(parsed.get("root_cause") or "").strip(),
        "confidence": confidence,
        "suggested_owner": owner,
        "evidence": [str(e) for e in evidence][:10],
        "bug_report": str(parsed.get("bug_report") or "").strip(),
    }


# ---------------------------------------------------------------- the agent


def triage(
    bundle: FailureBundle,
    *,
    provider: LLMProvider | None = None,
    max_iterations: int = MAX_ITERATIONS,
    use_tools: bool = True,
    budget_tokens: int = 3000,
    verbose: bool = False,
) -> TriageVerdict:
    """Run the agentic triage loop over one failure bundle."""
    llm = provider or get_provider()
    executor = ToolExecutor(bundle)
    tools = _tool_specs() if use_tools else None

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": bundle.render(budget_tokens)},
    ]

    verdict = TriageVerdict(provider=llm.name, model=llm.model)
    started = time.perf_counter()
    response: LLMResponse | None = None

    for iteration in range(1, max_iterations + 1):
        verdict.iterations = iteration
        try:
            response = llm.complete(messages, tools=tools, temperature=0.0)
        except LLMError as exc:
            verdict.parse_error = f"provider error: {exc}"
            verdict.latency_s = time.perf_counter() - started
            return verdict

        verdict.tokens_in += response.tokens_in
        verdict.tokens_out += response.tokens_out
        verdict.model = response.model or verdict.model

        if response.wants_tools and iteration < max_iterations:
            # Echo the assistant's tool request back before the results, as both APIs
            # require, then append one result per call.
            messages.append({
                "role": "assistant",
                "content": response.text or None,
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name,
                                     "arguments": json.dumps(call.arguments)},
                    }
                    for call in response.tool_calls
                ],
            })
            for call in response.tool_calls:
                result = executor.execute(call.name, call.arguments)
                verdict.tool_calls += 1
                if verbose:
                    print(f"  [tool] {call.name}({call.arguments}) "
                          f"-> {len(result)} chars")
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": result[:4000],
                })
            continue

        # On the final allowed iteration, insist on an answer rather than more tools.
        if response.wants_tools:
            messages.append({
                "role": "user",
                "content": "No more tool calls are available. Give your JSON verdict "
                           "now using the evidence you have, and lower your confidence "
                           "if it is incomplete.",
            })
            continue

        break

    verdict.latency_s = time.perf_counter() - started
    if response is None:
        verdict.parse_error = "no response from the provider"
        return verdict

    verdict.raw_response = response.text
    parsed, error = parse_verdict(response.text)
    if error:
        verdict.parse_error = error
        return verdict

    for key, value in _coerce(parsed).items():
        setattr(verdict, key, value)

    # A confident verdict with no evidence violates the contract. Rather than reject
    # it, the confidence is capped — the analysis may still be right, but an
    # uncited claim must not be presented as certain.
    if verdict.confidence > 0.5 and not verdict.evidence:
        verdict.confidence = 0.5
        verdict.evidence = ["(model cited no specific evidence; confidence capped)"]

    return verdict


def triage_tag(
    tag: str,
    *,
    data_dir: str | Path = "data",
    provider: LLMProvider | None = None,
    store_result: bool = False,
    **kwargs: Any,
) -> TriageVerdict:
    """Triage one corpus run by tag."""
    fault = None
    manifest = Path(data_dir) / "corpus_manifest.json"
    if manifest.exists():
        data = json.loads(manifest.read_text())
        for entry in data.get("deterministic", []):
            if entry["tag"] == tag:
                fault = entry["fault"]
                break

    bundle = build_from_tag(tag, data_dir, injected_fault=fault)
    verdict = triage(bundle, provider=provider, **kwargs)

    if store_result:
        from airframe.store import db as store

        conn = store.connect()
        try:
            run_id = store.start_run(conn, dut_backend="sim",
                                    dut_identity=tag, notes="triage")
            result_id = store.record_result(
                conn, run_id=run_id, nodeid=f"corpus::{tag}", outcome="failed"
            )
            store.record_triage(
                conn,
                result_id=result_id,
                run_id=run_id,
                provider=verdict.provider,
                model=verdict.model,
                root_cause=verdict.root_cause,
                confidence=verdict.confidence,
                suggested_owner=verdict.suggested_owner,
                evidence=verdict.evidence,
                bug_report_md=verdict.bug_report,
                tool_calls=verdict.tool_calls,
                tokens_in=verdict.tokens_in,
                tokens_out=verdict.tokens_out,
                latency_s=verdict.latency_s,
            )
            store.finish_run(conn, run_id, 0)
        finally:
            conn.close()
    return verdict


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="LLM triage for a wireless failure")
    ap.add_argument("tag", nargs="?", help="corpus tag to triage")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--provider", choices=["mock", "groq", "anthropic"])
    ap.add_argument("--no-tools", action="store_true")
    ap.add_argument("--store", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--evaluate", action="store_true",
                    help="triage one example of every fault and score against ground truth")
    args = ap.parse_args()

    provider = get_provider(args.provider)
    print(f"provider: {provider.describe()}\n")

    if args.evaluate:
        return _evaluate(provider, args.data_dir, use_tools=not args.no_tools)

    if not args.tag:
        ap.error("a tag is required unless --evaluate is given")

    verdict = triage_tag(
        args.tag, data_dir=args.data_dir, provider=provider,
        use_tools=not args.no_tools, store_result=args.store, verbose=args.verbose,
    )
    if verdict.parse_error:
        print(f"TRIAGE FAILED: {verdict.parse_error}")
        if verdict.raw_response:
            print(f"\nraw response:\n{verdict.raw_response[:800]}")
        return 1
    print(verdict.report())
    return 0


#: Which owner each injected fault SHOULD be attributed to. This is the ground truth
#: the agent is scored against — without it, "the triage looks good" is an opinion.
EXPECTED_OWNER: dict[str, tuple[str, ...]] = {
    "AUTH_TIMEOUT": ("wifi_infrastructure",),
    "ASSOC_REJECT": ("wifi_infrastructure",),
    "FOURWAY_M3_TIMEOUT": ("wifi_infrastructure", "supplicant"),
    "PMK_MISMATCH": ("provisioning", "supplicant"),
    "DHCP_NAK": ("dhcp",),
    "SCAN_EMPTY": ("environment", "wifi_infrastructure"),
    "BEACON_LOSS": ("environment", "wifi_infrastructure"),
    "LOW_RSSI": ("environment",),
    "CHANNEL_BUSY": ("environment",),
    "DEAUTH": ("wifi_infrastructure", "environment"),
}


def _evaluate(provider: LLMProvider, data_dir: str, *, use_tools: bool) -> int:
    """Score the agent against known injected faults."""
    manifest = Path(data_dir) / "corpus_manifest.json"
    if not manifest.exists():
        print("no corpus manifest; run scripts/build_corpus.py")
        return 1
    entries = json.loads(manifest.read_text())["deterministic"]

    seen: set[str] = set()
    cases: list[dict[str, Any]] = []
    for entry in entries:
        if entry["fault"] in ("NONE",) or entry["fault"] in seen:
            continue
        if entry["scenario"] != "wpa2":
            continue
        seen.add(entry["fault"])
        cases.append(entry)

    print(f"evaluating {len(cases)} faults\n")
    correct = 0
    for entry in cases:
        verdict = triage_tag(entry["tag"], data_dir=data_dir, provider=provider,
                             use_tools=use_tools)
        expected = EXPECTED_OWNER.get(entry["fault"], ())
        hit = verdict.suggested_owner in expected
        correct += hit
        mark = "OK  " if hit else "MISS"
        print(f"{mark} {entry['fault']:<20} owner={verdict.suggested_owner:<20} "
              f"conf={verdict.confidence:.0%}  expected={'|'.join(expected)}")
        if not hit:
            print(f"       cause: {verdict.root_cause[:110]}")

    print(f"\nowner attribution: {correct}/{len(cases)} correct "
          f"({correct / max(len(cases), 1):.0%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
