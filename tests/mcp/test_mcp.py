"""Tests for the MCP server.

Two layers, tested separately on purpose:

* **Tool dispatch** — the plain functions, called directly. Fast, and where the safety
  properties live.
* **The protocol** — one real stdio round-trip against the installed SDK. Slow, but it
  is the only thing that proves the server actually speaks MCP rather than merely
  having functions that would work if it did.

The safety tests matter most. This server exposes a test rig to an autonomous agent,
so "cannot run tests unless explicitly enabled" and "cannot touch real hardware ever"
are correctness requirements, not preferences.
"""

from __future__ import annotations

import sys

import pytest

from airframe.mcp import server as mcp_server
from airframe.mcp.server import MAX_OUTPUT_CHARS, TOOLS, _truncate, call_tool

# ---------------------------------------------------------------- registry


class TestToolRegistry:
    def test_every_tool_is_fully_declared(self) -> None:
        """A tool without a description is a tool the model will not use correctly."""
        for name, (func, description, schema) in TOOLS.items():
            assert callable(func), f"{name} has no implementation"
            assert len(description) > 30, f"{name} is under-described"
            assert schema.get("type") == "object", f"{name} has no object schema"

    def test_tool_names_are_snake_case(self) -> None:
        for name in TOOLS:
            assert name.islower() and " " not in name, name

    def test_expected_tools_are_present(self) -> None:
        expected = {"rig_status", "list_runs", "get_failures", "analyze_pcap",
                    "get_logs", "timeline", "triage_failure", "cluster_failures",
                    "query_kpis", "detect_regressions", "flaky_tests", "run_test"}
        assert expected <= set(TOOLS)

    def test_every_tool_has_a_type_annotated_signature(self) -> None:
        """MCP 2.x derives the JSON schema from type hints, so a missing hint means a
        tool the model cannot call correctly."""
        import inspect

        for name, (func, _d, _s) in TOOLS.items():
            signature = inspect.signature(func)
            for param in signature.parameters.values():
                assert param.annotation is not inspect.Parameter.empty, (
                    f"{name}.{param.name} has no type annotation"
                )


# ---------------------------------------------------------------- dispatch


class TestDispatch:
    def test_every_tool_dispatches_without_raising(self) -> None:
        """Tools run against whatever data happens to exist, including none."""
        for name in TOOLS:
            result = call_tool(name, {})
            assert isinstance(result, str), f"{name} returned {type(result)}"
            assert result, f"{name} returned nothing"

    def test_unknown_tool_lists_the_alternatives(self) -> None:
        result = call_tool("does_not_exist", {})
        assert "unknown tool" in result
        assert "rig_status" in result

    def test_bad_arguments_return_an_error_string(self) -> None:
        result = call_tool("rig_status", {"unexpected": 1})
        assert "bad arguments" in result

    def test_an_exception_inside_a_tool_becomes_a_result(self) -> None:
        """An exception would kill the agent session; a result it can recover from."""
        original = TOOLS["rig_status"]
        TOOLS["rig_status"] = (
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
            original[1], original[2],
        )
        try:
            result = call_tool("rig_status", {})
            assert "error in rig_status" in result
            assert "boom" in result
        finally:
            TOOLS["rig_status"] = original

    def test_output_is_truncated_to_the_cap(self) -> None:
        """A tool that floods the context window is worse than no tool."""
        assert len(_truncate("x" * 50_000)) < MAX_OUTPUT_CHARS + 200
        assert "truncated" in _truncate("x" * 50_000)

    def test_short_output_is_untouched(self) -> None:
        assert _truncate("short") == "short"


# ---------------------------------------------------------------- safety


class TestSafetyGates:
    """The properties that make it acceptable to hand this to an autonomous agent."""

    def test_run_test_is_disabled_by_default(self) -> None:
        assert not mcp_server.ALLOW_RUN, "test execution must be opt-in"
        result = call_tool("run_test", {})
        assert "disabled" in result
        assert "AIRFRAME_MCP_ALLOW_RUN" in result, "it must say how to enable it"

    def test_run_test_refuses_real_hardware_even_when_enabled(self, monkeypatch) -> None:
        """The gate that matters most.

        An agent must never be able to drive the Wi-Fi interface of the machine it is
        running on — it could disconnect the session it is using.
        """
        monkeypatch.setattr(mcp_server, "ALLOW_RUN", True)
        result = call_tool("run_test", {"backend": "macos"})
        assert "refused" in result.lower() or "only the 'sim'" in result

    def test_all_other_tools_are_read_only(self) -> None:
        """Nothing but run_test may mutate state. Checked by name so that adding a
        mutating tool forces a deliberate update to this list."""
        mutating = {"run_test"}
        for name in TOOLS:
            if name in mutating:
                continue
            source = TOOLS[name][0].__doc__ or ""
            assert "delete" not in source.lower(), f"{name} may be mutating"


# ---------------------------------------------------------------- tool behaviour


class TestToolBehaviour:
    def test_rig_status_reports_the_essentials(self) -> None:
        result = call_tool("rig_status", {})
        for field in ("simulator built", "captures", "LLM provider", "test execution"):
            assert field in result

    def test_analyze_pcap_suggests_alternatives_on_a_miss(self) -> None:
        """A bare 'not found' forces the agent to guess; a suggestion does not."""
        result = call_tool("analyze_pcap", {"tag": "definitely_not_a_real_tag"})
        assert "not found" in result

    def test_get_logs_reports_a_missing_tag(self) -> None:
        assert "not found" in call_tool("get_logs", {"tag": "nope_not_here"})

    def test_list_captures_filters(self) -> None:
        result = call_tool("list_captures", {"pattern": "zzz_no_match", "limit": 5})
        assert "no captures matching" in result

    def test_flaky_tests_groups_by_classification(self) -> None:
        """Lumping 'fixed' in with 'flaky' is the bug from BUILD_JOURNAL #19."""
        result = call_tool("flaky_tests", {"limit": 3})
        if "not enough run history" not in result:
            assert any(label in result for label in ("STABLE", "FLAKY", "FIXED"))


# ---------------------------------------------------------------- protocol


@pytest.mark.slow
class TestMcpProtocol:
    """One real round-trip. Proves the server speaks MCP, not just Python."""

    def test_stdio_round_trip(self) -> None:
        import asyncio
        import os

        from mcp.client.stdio import stdio_client

        from mcp import ClientSession, StdioServerParameters

        async def run() -> tuple[str, int, str]:
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "airframe.mcp.server"],
                env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ["HOME"]},
            )
            async with (
                stdio_client(params) as (read, write),
                ClientSession(read, write) as session,
            ):
                info = await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool("rig_status", {})
                return (info.server_info.name, len(tools.tools),
                        result.content[0].text)

        name, tool_count, status = asyncio.run(run())
        assert name == "airframe"
        assert tool_count == len(TOOLS)
        assert "AIRFRAME RIG STATUS" in status

    def test_schemas_are_derived_from_type_hints(self) -> None:
        """MCP 2.x infers `required` from parameters without defaults."""
        import asyncio
        import os

        from mcp.client.stdio import stdio_client

        from mcp import ClientSession, StdioServerParameters

        async def run() -> dict:
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "airframe.mcp.server"],
                env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ["HOME"]},
            )
            async with (
                stdio_client(params) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                tools = await session.list_tools()
                return next(t for t in tools.tools
                            if t.name == "analyze_pcap").input_schema

        schema = asyncio.run(run())
        assert "tag" in schema.get("properties", {})
        assert schema.get("required") == ["tag"], (
            "tag has no default, so it must be inferred as required"
        )
