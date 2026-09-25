"""Tests for the LLM triage layer: provider abstraction, bundles, the agent loop.

Everything here runs **offline and deterministically** against `MockProvider`. That is
the entire justification for putting the LLM behind an interface: an agent whose
behaviour can only be observed by calling a paid API is an agent nobody can write
assertions about.

What is actually being tested is the *scaffolding*, not the model — the loop
terminates, tools fail safely, malformed output is recovered, and an uncited claim
cannot be presented as confident. Those are the properties that stay true whichever
model is plugged in, and they are where the bugs live.
"""

from __future__ import annotations

import json

import pytest

from airframe.triage.agent import (
    MAX_ITERATIONS,
    OWNERS,
    ToolExecutor,
    TriageVerdict,
    _coerce,
    parse_verdict,
    triage,
)
from airframe.triage.bundle import CHARS_PER_TOKEN, FailureBundle, build_bundle
from airframe.triage.provider import (
    LLMProvider,
    LLMResponse,
    MockProvider,
    ToolCall,
    ToolSpec,
    get_provider,
)

# ---------------------------------------------------------------- providers


class TestProviderSelection:
    def test_falls_back_to_mock_without_a_key(self, monkeypatch) -> None:
        """The pipeline must stay runnable with no credentials at all."""
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("AIRFRAME_LLM_PROVIDER", raising=False)
        assert get_provider().name == "mock"

    def test_explicit_mock_is_honoured(self) -> None:
        assert get_provider("mock").name == "mock"

    def test_unknown_provider_raises_with_the_options_listed(self) -> None:
        from airframe.triage.provider import LLMError

        with pytest.raises(LLMError) as exc:
            get_provider("notaprovider")
        assert "groq" in str(exc.value)

    def test_unavailable_provider_degrades_rather_than_raising(self, monkeypatch) -> None:
        """A missing key must downgrade triage, not break the tool."""
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        assert get_provider("groq").name == "mock"


class TestMockProvider:
    def test_is_deterministic(self) -> None:
        messages = [{"role": "user", "content": "deauth reason=15 retransmitting M2"}]
        a = MockProvider(use_tools=False).complete(messages)
        b = MockProvider(use_tools=False).complete(messages)
        assert a.text == b.text

    def test_requests_a_tool_on_the_first_turn(self) -> None:
        """So the agentic loop's tool path is exercised by offline tests."""
        tools = [ToolSpec("analyze_pcap", "d", {"type": "object", "properties": {}})]
        response = MockProvider().complete([{"role": "user", "content": "x"}], tools=tools)
        assert response.wants_tools

    def test_does_not_request_tools_once_results_are_present(self) -> None:
        """Otherwise it would loop forever asking for the same tool."""
        tools = [ToolSpec("analyze_pcap", "d", {"type": "object", "properties": {}})]
        messages = [
            {"role": "user", "content": "deauth reason=15"},
            {"role": "tool", "tool_call_id": "1", "content": "result"},
        ]
        assert not MockProvider().complete(messages, tools=tools).wants_tools

    @pytest.mark.parametrize(
        "blob,expected_owner",
        [
            ("deauth reason=15 retransmitting m2", "wifi_infrastructure"),
            ("mic verification failed reason=23 pmk mismatch", "provisioning"),
            ("dhcpnak no ipv4 address", "dhcp"),
            ("networks=0 never heard", "environment"),
        ],
    )
    def test_diagnoses_distinct_faults_differently(self, blob, expected_owner) -> None:
        """A mock returning one constant would make every downstream test vacuous."""
        response = MockProvider(use_tools=False).complete(
            [{"role": "user", "content": blob}]
        )
        assert json.loads(response.text)["suggested_owner"] == expected_owner

    def test_admits_ignorance_on_unrecognised_input(self) -> None:
        response = MockProvider(use_tools=False).complete(
            [{"role": "user", "content": "nothing recognisable here at all"}]
        )
        verdict = json.loads(response.text)
        assert verdict["confidence"] < 0.5
        assert verdict["suggested_owner"] == "unknown"


# ---------------------------------------------------------------- bundles


class TestFailureBundle:
    def _big_bundle(self) -> FailureBundle:
        bundle = FailureBundle(tag="t", nodeid="tests/x.py::test_y")
        bundle.log_templates = [f"  x{i:<4} template number {i} with padding" * 3
                                for i in range(200)]
        bundle.kpi_deltas = [f"endpoint{i} latency up {i}%" for i in range(100)]
        bundle.log_summary = "summary " * 200
        bundle.error_window = ["  1000ms X [log] something broke"] * 20
        return bundle

    def test_respects_the_token_budget(self) -> None:
        text = self._big_bundle().render(budget_tokens=500)
        assert len(text) <= 500 * CHARS_PER_TOKEN * 1.6, "budget was ignored"

    def test_drops_low_value_sections_first(self) -> None:
        """Templates and KPI tables go before the error window and the header."""
        bundle = self._big_bundle()
        text = bundle.render(budget_tokens=300)
        assert bundle.truncated
        assert "FAILURE: t" in text, "the header must never be dropped"
        assert "LOG TEMPLATES" not in text, "templates should be dropped first"

    def test_small_bundle_is_not_truncated(self) -> None:
        bundle = FailureBundle(tag="t")
        bundle.error_window = ["  0ms X [log] boom"]
        bundle.render(budget_tokens=3000)
        assert not bundle.truncated

    def test_renders_without_any_artifacts(self) -> None:
        """Triage is often run with logs but no capture, or neither."""
        text = FailureBundle(tag="orphan").render()
        assert "orphan" in text

    def test_build_bundle_tolerates_missing_files(self) -> None:
        bundle = build_bundle(tag="nope", log_path="/nonexistent.log",
                              pcap_path="/nonexistent.pcap")
        assert bundle.tag == "nope"
        assert bundle.forensics is None
        assert bundle.render()

    def test_as_dict_is_serialisable(self) -> None:
        assert json.dumps(FailureBundle(tag="t").as_dict())


# ---------------------------------------------------------------- verdict parsing


class TestVerdictParsing:
    def test_parses_bare_json(self) -> None:
        parsed, error = parse_verdict('{"root_cause": "x", "confidence": 0.9}')
        assert error is None
        assert parsed["root_cause"] == "x"

    def test_parses_json_in_a_code_fence(self) -> None:
        """Models wrap output in fences despite instructions not to."""
        parsed, error = parse_verdict('```json\n{"root_cause": "fenced"}\n```')
        assert error is None
        assert parsed["root_cause"] == "fenced"

    def test_parses_json_surrounded_by_prose(self) -> None:
        text = 'Here is my analysis:\n{"root_cause": "buried"}\nHope that helps!'
        parsed, error = parse_verdict(text)
        assert error is None
        assert parsed["root_cause"] == "buried"

    def test_reports_an_error_for_unparseable_output(self) -> None:
        parsed, error = parse_verdict("I could not determine the cause, sorry.")
        assert parsed == {}
        assert error is not None

    def test_rejects_json_without_a_root_cause(self) -> None:
        """Valid JSON of the wrong shape is still not a verdict."""
        _parsed, error = parse_verdict('{"something": "else"}')
        assert error is not None


class TestVerdictCoercion:
    def test_clamps_confidence_into_range(self) -> None:
        assert _coerce({"root_cause": "x", "confidence": 5.0})["confidence"] == 1.0
        assert _coerce({"root_cause": "x", "confidence": -2})["confidence"] == 0.0

    def test_non_numeric_confidence_becomes_zero(self) -> None:
        assert _coerce({"root_cause": "x", "confidence": "high"})["confidence"] == 0.0

    def test_unknown_owner_maps_to_a_valid_value(self) -> None:
        """A free-text owner cannot be routed to a team, so it must be constrained."""
        assert _coerce({"root_cause": "x", "suggested_owner": "the wifi team"})[
            "suggested_owner"] in OWNERS

    def test_string_evidence_is_wrapped_into_a_list(self) -> None:
        assert _coerce({"root_cause": "x", "evidence": "one fact"})["evidence"] == ["one fact"]

    def test_evidence_is_capped(self) -> None:
        coerced = _coerce({"root_cause": "x", "evidence": [f"e{i}" for i in range(50)]})
        assert len(coerced["evidence"]) <= 10


# ---------------------------------------------------------------- tools


class TestToolExecutor:
    def test_unknown_tool_returns_an_error_string(self) -> None:
        """Never raise: the model can recover from a bad tool result, not an exception."""
        result = ToolExecutor(FailureBundle(tag="t")).execute("no_such_tool", {})
        assert "unknown tool" in result

    def test_bad_arguments_are_reported_not_raised(self) -> None:
        result = ToolExecutor(FailureBundle(tag="t")).execute(
            "lookup_ieee_code", {"code": "not-an-int", "kind": "reason"}
        )
        assert isinstance(result, str)

    def test_missing_artifacts_are_reported_gracefully(self) -> None:
        executor = ToolExecutor(FailureBundle(tag="t"))
        assert "no log file" in executor.execute("get_log_lines", {})
        assert "no packet capture" in executor.execute("analyze_pcap", {})

    def test_ieee_lookup_returns_the_meaning(self) -> None:
        result = ToolExecutor(FailureBundle(tag="t")).execute(
            "lookup_ieee_code", {"code": 15, "kind": "reason"}
        )
        assert "4-Way Handshake timeout" in result

    def test_unknown_code_says_so(self) -> None:
        result = ToolExecutor(FailureBundle(tag="t")).execute(
            "lookup_ieee_code", {"code": 9999, "kind": "reason"}
        )
        assert "not in the reference table" in result

    def test_calls_are_logged(self) -> None:
        executor = ToolExecutor(FailureBundle(tag="t"))
        executor.execute("get_stage_timings", {})
        assert executor.call_log


# ---------------------------------------------------------------- the agent loop


class _LoopForever(LLMProvider):
    """A model that only ever asks for tools — the pathological case."""

    name = "loopforever"
    model = "loop"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages, *, tools=None, temperature=0.0, max_tokens=2048):
        self.calls += 1
        if tools:
            return LLMResponse(
                tool_calls=[ToolCall(id=f"c{self.calls}", name="get_stage_timings",
                                     arguments={})],
                finish_reason="tool_calls",
            )
        return LLMResponse(text='{"root_cause": "gave up", "confidence": 0.1}')


class _NoEvidence(LLMProvider):
    """A model that claims high confidence while citing nothing."""

    name = "noevidence"
    model = "n"

    def complete(self, messages, *, tools=None, temperature=0.0, max_tokens=2048):
        return LLMResponse(text=json.dumps({
            "root_cause": "definitely the AP",
            "confidence": 0.99,
            "suggested_owner": "wifi_infrastructure",
            "evidence": [],
        }))


class _Broken(LLMProvider):
    name = "broken"
    model = "b"

    def complete(self, messages, *, tools=None, temperature=0.0, max_tokens=2048):
        from airframe.triage.provider import LLMError

        raise LLMError("upstream is down")


class TestAgentLoop:
    def _bundle(self) -> FailureBundle:
        bundle = FailureBundle(tag="t", nodeid="tests/x.py::test_y")
        bundle.error_window = ["  2000ms X [log] deauth reason=15 retransmitting M2"]
        return bundle

    def test_produces_a_structured_verdict(self) -> None:
        verdict = triage(self._bundle(), provider=MockProvider())
        assert verdict.valid
        assert verdict.root_cause
        assert verdict.suggested_owner in OWNERS
        assert 0.0 <= verdict.confidence <= 1.0

    def test_executes_tools_and_records_the_count(self) -> None:
        verdict = triage(self._bundle(), provider=MockProvider())
        assert verdict.tool_calls >= 1
        assert verdict.iterations >= 2

    def test_can_run_without_tools(self) -> None:
        verdict = triage(self._bundle(), provider=MockProvider(), use_tools=False)
        assert verdict.valid
        assert verdict.tool_calls == 0

    def test_terminates_on_a_model_that_only_asks_for_tools(self) -> None:
        """Without a cap this bills until someone notices."""
        provider = _LoopForever()
        verdict = triage(self._bundle(), provider=provider)
        assert verdict.iterations <= MAX_ITERATIONS
        assert provider.calls <= MAX_ITERATIONS + 1

    def test_caps_confidence_when_no_evidence_is_cited(self) -> None:
        """An uncited claim must not be presented as certain — the main guardrail."""
        verdict = triage(self._bundle(), provider=_NoEvidence())
        assert verdict.confidence <= 0.5, "99% confidence with zero evidence was accepted"
        assert verdict.evidence, "the cap should record why it was applied"

    def test_provider_failure_is_reported_not_raised(self) -> None:
        verdict = triage(self._bundle(), provider=_Broken())
        assert not verdict.valid
        assert verdict.parse_error is not None
        assert "upstream is down" in verdict.parse_error

    def test_records_token_and_latency_accounting(self) -> None:
        verdict = triage(self._bundle(), provider=MockProvider())
        assert verdict.tokens_in > 0
        assert verdict.latency_s >= 0.0
        assert verdict.provider == "mock"

    def test_is_deterministic_for_the_same_bundle(self) -> None:
        """Two engineers reading the same bug must get the same story."""
        a = triage(self._bundle(), provider=MockProvider())
        b = triage(self._bundle(), provider=MockProvider())
        assert a.root_cause == b.root_cause
        assert a.confidence == b.confidence


class TestVerdictReporting:
    def test_low_confidence_is_flagged_in_the_report(self) -> None:
        verdict = TriageVerdict(root_cause="maybe", confidence=0.3, provider="mock")
        assert not verdict.is_confident
        assert "hypothesis" in verdict.report()

    def test_report_includes_evidence_and_accounting(self) -> None:
        verdict = TriageVerdict(root_cause="x", confidence=0.9, provider="mock",
                                model="m", evidence=["fact one"], tool_calls=2)
        text = verdict.report()
        assert "fact one" in text
        assert "2 tool call" in text

    def test_invalid_without_a_root_cause(self) -> None:
        assert not TriageVerdict().valid
