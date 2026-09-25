"""LLM provider abstraction.

The design decision worth defending: **the agent never imports a vendor SDK.**
Everything goes through the `LLMProvider` interface below, which means:

* **Groq** for real inference (OpenAI-compatible API, fast, generous free tier),
* **Mock** for tests and CI — deterministic, offline, no key, no cost,
* **Anthropic** as a drop-in alternative,

and swapping between them is one config value. Three reasons this matters more than
it looks:

1. **Tests must not need a network or a key.** A test suite that calls a paid API is
   slow, flaky, costs money per run, and cannot run in CI. The Mock provider makes
   the entire triage pipeline testable offline and deterministically — which is the
   only way to assert on an agent's behaviour at all.
2. **Providers change.** Model names get deprecated, pricing changes, rate limits
   bite. A vendor name compiled into your agent logic becomes a migration project.
3. **It is the honest engineering answer**, and "don't hardcode your vendor" is
   exactly the sort of design decision an interviewer will push on.

Model selection is done by **querying the provider's live model list**, not by
hardcoding a name. Groq's lineup rotates; a hardcoded model id is a time bomb that
goes off as a 404 months later.
"""

from __future__ import annotations

import json
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]


def load_dotenv(path: str | Path | None = None) -> dict[str, str]:
    """Minimal .env loader. Does not overwrite variables already in the environment.

    Deliberately tiny rather than depending on python-dotenv: it is fifteen lines and
    one fewer dependency. Existing env vars win, so CI secrets always override a
    stray local file.
    """
    target = Path(path) if path else REPO_ROOT / ".env"
    loaded: dict[str, str] = {}
    if not target.exists():
        return loaded
    for raw in target.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


@dataclass
class ToolSpec:
    """A tool the model may call, in the JSON-schema form both APIs expect."""

    name: str
    description: str
    parameters: dict[str, Any]

    def as_openai_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    model: str = ""
    latency_s: float = 0.0
    finish_reason: str = ""

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class LLMError(RuntimeError):
    pass


class LLMProvider(ABC):
    name: str = "abstract"
    model: str = ""

    @abstractmethod
    def complete(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """One turn. Must not raise for ordinary model behaviour, only for transport."""

    @property
    def available(self) -> bool:
        return True

    def describe(self) -> str:
        return f"{self.name}({self.model})"


# ---------------------------------------------------------------- mock


class MockProvider(LLMProvider):
    """Deterministic offline provider.

    Not a stub that returns "OK": it does simple keyword analysis on the failure
    bundle and produces a *plausible, structured* verdict. That matters because the
    tests assert on the shape and content of triage output, and a provider returning
    a constant would make those tests vacuous.

    It also deliberately exercises the tool-calling path (requesting one tool on the
    first turn), so the agentic loop itself is covered by offline tests rather than
    only by whatever a live model happens to do.
    """

    name = "mock"
    model = "mock-deterministic-v1"

    def __init__(self, *, use_tools: bool = True) -> None:
        self.use_tools = use_tools
        self.calls = 0

    def complete(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        self.calls += 1
        blob = "\n".join(str(m.get("content") or "") for m in messages).lower()

        # First turn: ask for one tool, so the loop's tool path is exercised.
        already_used_tools = any(m.get("role") == "tool" for m in messages)
        if tools and self.use_tools and not already_used_tools:
            wanted = next(
                (t for t in tools if t.name in ("analyze_pcap", "get_run_logs")), tools[0]
            )
            args: dict[str, Any] = {}
            if "run_id" in wanted.parameters.get("properties", {}):
                args["run_id"] = 1
            if "tag" in wanted.parameters.get("properties", {}):
                m = re.search(r"tag[\"':\s]+([\w.-]+)", blob)
                args["tag"] = m.group(1) if m else "unknown"
            return LLMResponse(
                tool_calls=[ToolCall(id="mock-call-1", name=wanted.name, arguments=args)],
                model=self.model,
                finish_reason="tool_calls",
                tokens_in=len(blob) // 4,
                tokens_out=24,
            )

        verdict = self._diagnose(blob)
        return LLMResponse(
            text=json.dumps(verdict, indent=2),
            model=self.model,
            finish_reason="stop",
            tokens_in=len(blob) // 4,
            tokens_out=len(json.dumps(verdict)) // 4,
        )

    @staticmethod
    def _diagnose(blob: str) -> dict[str, Any]:
        """Rule-based stand-in for model reasoning, ordered most-specific first."""
        rules: list[tuple[tuple[str, ...], dict[str, Any]]] = [
            (
                ("reason=23", "ieee8021x_failed", "pmk mismatch", "mic verification failed"),
                {
                    "root_cause": "PMK mismatch: the station's MIC failed verification "
                                  "during the 4-way handshake, which indicates incorrect "
                                  "credentials rather than a network fault",
                    "confidence": 0.9,
                    "suggested_owner": "provisioning",
                    "evidence": ["EAPOL-Key MIC verification failed at M2",
                                 "deauth reason 23 (IEEE 802.1X authentication failed)"],
                },
            ),
            (
                ("reason=15", "fourway_handshake_timeout", "retransmitting m2"),
                {
                    "root_cause": "4-way handshake timeout: the station sent M2 and the "
                                  "access point never responded with M3. The client "
                                  "retried correctly, so the authenticator on the AP side "
                                  "is at fault",
                    "confidence": 0.88,
                    "suggested_owner": "wifi_infrastructure",
                    "evidence": ["M2 retransmitted multiple times",
                                 "M3 never observed in the capture",
                                 "deauth reason 15 (4-Way Handshake timeout)"],
                },
            ),
            (
                ("dhcpnak", "no ipv4 address", "dhcp_failed"),
                {
                    "root_cause": "DHCP failure on a healthy radio link: association and "
                                  "key exchange both completed, then the DHCP server "
                                  "refused the address request. This is a network-services "
                                  "problem, not a wireless one",
                    "confidence": 0.85,
                    "suggested_owner": "dhcp",
                    "evidence": ["4-way handshake completed successfully",
                                 "DHCPNAK received from the server",
                                 "no IPv4 address assigned"],
                },
            ),
            (
                ("auth timeout", "status=auth_timeout"),
                {
                    "root_cause": "Authentication timeout: the AP did not respond to the "
                                  "authentication request within the supplicant timeout",
                    "confidence": 0.82,
                    "suggested_owner": "wifi_infrastructure",
                    "evidence": ["auth request sent, no auth response received",
                                 "association never attempted"],
                },
            ),
            (
                ("assoc rejected", "ap_unable_to_handle_sta", "status=17"),
                {
                    "root_cause": "Association rejected by the access point with a "
                                  "non-success status code, most commonly because the AP "
                                  "is at its client capacity",
                    "confidence": 0.8,
                    "suggested_owner": "wifi_infrastructure",
                    "evidence": ["association response carried a non-zero status code"],
                },
            ),
            (
                ("networks=0", "never heard", "scan_empty"),
                {
                    "root_cause": "No networks found during the scan: the AP was never "
                                  "heard, so it is powered off, out of range, or on a "
                                  "channel that was not scanned",
                    "confidence": 0.78,
                    "suggested_owner": "environment",
                    "evidence": ["scan completed with zero results"],
                },
            ),
            (
                ("beacon miss", "reason=34", "beacon_loss"),
                {
                    "root_cause": "Beacon loss after a successful connection: the station "
                                  "stopped hearing the AP, consistent with the client "
                                  "moving out of range or the AP resetting",
                    "confidence": 0.8,
                    "suggested_owner": "environment",
                    "evidence": ["consecutive beacon misses logged",
                                 "disconnect reason 34"],
                },
            ),
            (
                ("signal below usable threshold", "degraded_weak_signal",
                 "degraded_rssi_collapse", "weak_signal"),
                {
                    "root_cause": "Weak signal: RSSI fell below the usable threshold, so "
                                  "rate adaptation dropped to the lowest MCS. The link "
                                  "associated but throughput and reliability are degraded",
                    "confidence": 0.75,
                    "suggested_owner": "environment",
                    "evidence": ["RSSI below the -80 dBm usable threshold",
                                 "link associated successfully but degraded"],
                },
            ),
            (
                ("reason=1 reason_name=unspecified", "deauth received reason=1",
                 "torn down with reason 1"),
                {
                    "root_cause": "The access point deauthenticated the station with an "
                                  "unspecified reason after a successful association. The "
                                  "link was healthy up to that point, so the AP initiated "
                                  "the teardown",
                    "confidence": 0.72,
                    "suggested_owner": "wifi_infrastructure",
                    "evidence": ["association and 4-way handshake both completed",
                                 "AP-initiated deauth with reason code 1 (unspecified)"],
                },
            ),
            (
                ("cca_busy", "channel congestion", "degraded_high_retry"),
                {
                    "root_cause": "Channel congestion: the link connected successfully but "
                                  "retry rates are elevated, indicating contention on the "
                                  "operating channel",
                    "confidence": 0.7,
                    "suggested_owner": "environment",
                    "evidence": ["elevated retry rate on data frames",
                                 "high CCA-busy percentage reported"],
                },
            ),
        ]
        for keys, verdict in rules:
            if any(k in blob for k in keys):
                return {**verdict, "bug_report": _mock_bug_report(verdict)}

        return {
            "root_cause": "Insufficient evidence to determine a root cause from the "
                          "supplied artifacts",
            "confidence": 0.2,
            "suggested_owner": "unknown",
            "evidence": [],
            "bug_report": "Insufficient evidence; more artifacts are required.",
        }


def _mock_bug_report(verdict: dict[str, Any]) -> str:
    bullets = "\n".join(f"- {e}" for e in verdict.get("evidence", []))
    return (
        f"## Summary\n{verdict['root_cause']}\n\n"
        f"## Evidence\n{bullets or '- none recorded'}\n\n"
        f"## Suggested owner\n{verdict['suggested_owner']}\n"
    )


# ---------------------------------------------------------------- groq


class GroqProvider(LLMProvider):
    """Groq via its OpenAI-compatible endpoint.

    Uses the `openai` SDK pointed at Groq's base URL rather than a Groq-specific
    client, which keeps the same code path usable for any OpenAI-compatible provider.

    The model is chosen by querying `/models` at construction time and preferring
    known-good families, because Groq's catalogue rotates and a hardcoded id
    eventually 404s. An explicit `model=` always wins.
    """

    name = "groq"
    BASE_URL = "https://api.groq.com/openai/v1"

    #: Preference order, matched as substrings against the live model list. Larger
    #: instruct models first (triage needs reasoning), with smaller ones as fallback.
    PREFERRED = (
        "llama-3.3-70b-versatile",
        "llama-3.3-70b",
        "llama-3.1-70b",
        "gpt-oss-120b",
        "qwen-2.5-32b",
        "llama-3.1-8b-instant",
        "llama3-70b",
    )

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        load_dotenv()
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self._client: Any = None
        self.model = model or ""
        self._init_error: str | None = None

        if not self.api_key:
            self._init_error = (
                "GROQ_API_KEY is not set. Put it in .env as GROQ_API_KEY=... "
                "(get one free at https://console.groq.com)"
            )
            return
        try:
            from openai import OpenAI

            self._client = OpenAI(api_key=self.api_key, base_url=self.BASE_URL,
                                  timeout=60.0, max_retries=2)
            if not self.model:
                self.model = self._pick_model()
        except Exception as exc:                      # noqa: BLE001 - surfaced below
            self._init_error = f"could not initialise Groq client: {exc}"

    def _pick_model(self) -> str:
        """Query the live model list and pick the best available."""
        try:
            available = [m.id for m in self._client.models.list().data]
        except Exception as exc:                      # noqa: BLE001
            raise LLMError(f"could not list Groq models: {exc}") from exc
        for preferred in self.PREFERRED:
            for candidate in available:
                if preferred in candidate:
                    return candidate
        # Nothing recognised: take any chat-capable model rather than failing outright.
        chat = [m for m in available if "whisper" not in m and "guard" not in m]
        if not chat:
            raise LLMError(f"no usable Groq model in: {available}")
        return chat[0]

    @property
    def available(self) -> bool:
        return self._client is not None and self._init_error is None

    def complete(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        if not self.available:
            raise LLMError(self._init_error or "Groq provider is unavailable")

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            # temperature 0 for triage: the same failure must yield the same verdict,
            # or the report cannot be trusted or regression-tested.
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = [t.as_openai_tool() for t in tools]
            kwargs["tool_choice"] = "auto"

        start = time.perf_counter()
        try:
            completion = self._client.chat.completions.create(**kwargs)
        except Exception as exc:                      # noqa: BLE001
            raise LLMError(f"Groq request failed: {exc}") from exc
        latency = time.perf_counter() - start

        choice = completion.choices[0]
        calls: list[ToolCall] = []
        for raw in getattr(choice.message, "tool_calls", None) or []:
            try:
                args = json.loads(raw.function.arguments or "{}")
            except json.JSONDecodeError:
                # Models occasionally emit malformed JSON arguments. Recording the
                # raw string keeps the loop alive and makes the failure debuggable
                # instead of crashing the whole triage.
                args = {"_raw": raw.function.arguments}
            calls.append(ToolCall(id=raw.id, name=raw.function.name, arguments=args))

        usage = getattr(completion, "usage", None)
        return LLMResponse(
            text=choice.message.content or "",
            tool_calls=calls,
            tokens_in=getattr(usage, "prompt_tokens", 0) or 0,
            tokens_out=getattr(usage, "completion_tokens", 0) or 0,
            model=completion.model,
            latency_s=latency,
            finish_reason=choice.finish_reason or "",
        )


# ---------------------------------------------------------------- anthropic


class AnthropicProvider(LLMProvider):
    """Anthropic Claude. Included to prove the interface is genuinely portable.

    Anthropic's API differs from OpenAI's in shape — the system prompt is a separate
    parameter, tools use `input_schema` rather than `parameters`, and content arrives
    as blocks. Adapting all of that behind the same `complete()` signature is what
    demonstrates the abstraction is real rather than an OpenAI wrapper with extra steps.
    """

    name = "anthropic"

    def __init__(self, *, api_key: str | None = None,
                 model: str = "claude-haiku-4-5-20251001") -> None:
        load_dotenv()
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self._client: Any = None
        self._init_error: str | None = None
        if not self.api_key:
            self._init_error = "ANTHROPIC_API_KEY is not set"
            return
        try:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self.api_key)
        except ImportError:
            self._init_error = "the anthropic package is not installed"
        except Exception as exc:                      # noqa: BLE001
            self._init_error = str(exc)

    @property
    def available(self) -> bool:
        return self._client is not None and self._init_error is None

    def complete(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        if not self.available:
            raise LLMError(self._init_error or "Anthropic provider is unavailable")

        # Anthropic takes the system prompt as its own parameter.
        system = "\n\n".join(
            str(m["content"]) for m in messages if m.get("role") == "system"
        )
        convo = [m for m in messages if m.get("role") != "system"]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": convo,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in tools
            ]

        start = time.perf_counter()
        try:
            message = self._client.messages.create(**kwargs)
        except Exception as exc:                      # noqa: BLE001
            raise LLMError(f"Anthropic request failed: {exc}") from exc
        latency = time.perf_counter() - start

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in message.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name,
                                      arguments=dict(block.input)))

        return LLMResponse(
            text="".join(text_parts),
            tool_calls=calls,
            tokens_in=message.usage.input_tokens,
            tokens_out=message.usage.output_tokens,
            model=message.model,
            latency_s=latency,
            finish_reason=message.stop_reason or "",
        )


# ---------------------------------------------------------------- factory


PROVIDERS = {"mock": MockProvider, "groq": GroqProvider, "anthropic": AnthropicProvider}


def get_provider(name: str | None = None, **kwargs: Any) -> LLMProvider:
    """Construct a provider by name, falling back to Mock with a clear message.

    Falling back rather than raising is deliberate: the triage pipeline must remain
    runnable with no key at all, so a missing key degrades to deterministic offline
    triage instead of breaking the tool.
    """
    load_dotenv()
    chosen = (name or os.environ.get("AIRFRAME_LLM_PROVIDER", "")).lower()

    if not chosen:
        chosen = "groq" if os.environ.get("GROQ_API_KEY") else "mock"

    if chosen not in PROVIDERS:
        raise LLMError(f"unknown provider {chosen!r}; available: {', '.join(PROVIDERS)}")

    provider = PROVIDERS[chosen](**kwargs)
    if not provider.available and chosen != "mock":
        reason = getattr(provider, "_init_error", "unavailable")
        print(f"[airframe] {chosen} provider unavailable ({reason}); using mock",
              flush=True)
        return MockProvider()
    return provider


def _main() -> int:
    """`python -m airframe.triage.provider` — show which providers are usable."""
    load_dotenv()
    print("provider availability:")
    for name in PROVIDERS:
        try:
            provider = PROVIDERS[name]()
            status = "READY" if provider.available else "unavailable"
            detail = provider.describe() if provider.available else (
                getattr(provider, "_init_error", "") or ""
            )
            print(f"  {name:<12} {status:<14} {detail}")
        except Exception as exc:                      # noqa: BLE001
            print(f"  {name:<12} error          {exc}")
    print(f"\ndefault selection -> {get_provider().describe()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
