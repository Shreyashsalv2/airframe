"""MCP server — exposing the test rig as tools an AI agent can drive.

This is the JD's "MCP-based tooling" bullet made concrete. Once this server is
registered, Claude Code (or any MCP client) can operate the wireless test lab
conversationally:

    "run the WPA3 connectivity tests and triage anything that fails"
    "what's the flakiest test in the last ten runs?"
    "analyse the capture from wpa2_FOURWAY_M3_TIMEOUT_1010 and tell me what broke"

Why MCP rather than a REST API or a CLI wrapper
-----------------------------------------------
MCP is a protocol for exposing *capabilities* to a model with enough structure that
the model can decide when to use them: each tool carries a name, a description and a
JSON schema, and the client handles discovery. The practical consequence is that the
agent needs no bespoke integration — the same server works with any MCP client, and
adding a tool requires no client-side change at all.

Design constraints, and the reasoning behind each
-------------------------------------------------
**Read-only by default.** Every tool here inspects stored results and artifacts.
`run_test` is the one exception, it is explicitly gated behind an environment
variable, and it can only run tests against the *simulator* — never real hardware.
An agent that can reconfigure the Wi-Fi of the machine it is running on is a bad idea
however well it is prompted.

**Every tool returns text, not objects.** Models consume text. Returning a formatted,
self-explaining string beats returning JSON the model must then parse and interpret.

**Bounded output.** Tools cap what they return. A tool that dumps 4,000 log lines
into a context window is worse than no tool — it crowds out the model's own reasoning
and the useful part is buried anyway.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = REPO_ROOT / "data"

#: Running tests mutates state and costs time, so it is opt-in.
ALLOW_RUN = os.environ.get("AIRFRAME_MCP_ALLOW_RUN", "").lower() in ("1", "true", "yes")

#: Hard cap on characters returned by any single tool.
MAX_OUTPUT_CHARS = 6000


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more characters]"


# ---------------------------------------------------------------- tool bodies
#
# Each is a plain function so it can be unit-tested without an MCP client. The MCP
# layer at the bottom is a thin adapter over these.


def tool_list_runs(limit: int = 20) -> str:
    """Recent test runs from the result store."""
    from airframe.store import db as store

    conn = store.connect()
    try:
        rows = conn.execute(
            """SELECT r.id, r.started_at, r.dut_backend, r.dut_identity, r.exit_status,
                      COUNT(res.id) AS n_results,
                      SUM(CASE WHEN res.outcome IN ('failed','error') THEN 1 ELSE 0 END)
                        AS n_failed
               FROM runs r LEFT JOIN results res ON res.run_id = r.id
               GROUP BY r.id ORDER BY r.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return "no runs recorded yet"
    lines = [f"{'run':<6} {'started':<26} {'backend':<8} {'tests':<7} {'failed':<7} identity"]
    for row in rows:
        lines.append(
            f"{row['id']:<6} {str(row['started_at'])[:24]:<26} "
            f"{row['dut_backend']:<8} {row['n_results'] or 0:<7} "
            f"{row['n_failed'] or 0:<7} {row['dut_identity'] or ''}"
        )
    return "\n".join(lines)


def tool_get_failures(run_id: int | None = None, limit: int = 25) -> str:
    """Failing tests, newest run first when no run is named."""
    from airframe.store import db as store

    conn = store.connect()
    try:
        if run_id is None:
            run_id = store.latest_run_id(conn)
        if run_id is None:
            return "no runs recorded yet"
        rows = store.failed_results(conn, run_id)[:limit]
    finally:
        conn.close()

    if not rows:
        return f"run {run_id}: no failures"
    lines = [f"run {run_id}: {len(rows)} failure(s)"]
    for row in rows:
        lines.append(f"\n{row['nodeid']}")
        if row["failure_message"]:
            lines.append(f"  {row['failure_message'][:200]}")
    return _truncate("\n".join(lines))


def tool_list_captures(pattern: str = "", limit: int = 40) -> str:
    """Available packet captures, optionally filtered by a substring."""
    pcaps = sorted((DATA_DIR / "pcaps").glob("*.pcap"))
    if pattern:
        pcaps = [p for p in pcaps if pattern.lower() in p.stem.lower()]
    if not pcaps:
        return f"no captures matching {pattern!r}"
    listed = pcaps[:limit]
    lines = [f"{len(pcaps)} capture(s)" + (f", showing {len(listed)}" if len(pcaps) > limit else "")]
    lines.extend(f"  {p.stem}  ({p.stat().st_size} bytes)" for p in listed)
    return "\n".join(lines)


def tool_analyze_pcap(tag: str, detail: str = "verdict") -> str:
    """Run 802.11 forensics on a capture. `detail` is verdict | frames | anomalies | all."""
    from airframe.pcap.anomaly import scan_capture
    from airframe.pcap.assoc import analyse
    from airframe.pcap.dissect import load_capture

    path = DATA_DIR / "pcaps" / f"{tag}.pcap"
    if not path.exists():
        candidates = [p.stem for p in (DATA_DIR / "pcaps").glob(f"*{tag}*.pcap")][:5]
        hint = f" Did you mean: {', '.join(candidates)}?" if candidates else ""
        return f"capture {tag!r} not found.{hint}"

    cap = load_capture(path)
    parts: list[str] = []

    if detail in ("verdict", "all"):
        parts.append(analyse(cap).report())
    if detail in ("anomalies", "all"):
        found = scan_capture(cap)
        parts.append("ANOMALIES:\n" + ("\n".join(f"  {a}" for a in found)
                                       if found else "  none detected"))
    if detail in ("frames", "all"):
        parts.append("FRAMES:\n" + "\n".join(f"  {f.summary()}" for f in list(cap)[:60]))
    return _truncate("\n\n".join(parts))


def tool_get_logs(tag: str, contains: str = "", level: str = "", limit: int = 50) -> str:
    """Log lines for a run, optionally filtered."""
    from airframe.logs.parse import parse_file

    path = DATA_DIR / "logs" / f"{tag}.log"
    if not path.exists():
        return f"log for {tag!r} not found"
    lines = parse_file(path)
    selected = [
        line for line in lines
        if (not contains or contains.lower() in line.message.lower())
        and (not level or line.level == level.upper())
    ][:limit]
    if not selected:
        return f"no lines matched (contains={contains!r}, level={level!r})"
    return _truncate("\n".join(str(line) for line in selected))


def tool_timeline(tag: str, errors_only: bool = True) -> str:
    """Correlated timeline of logs and packets for one run."""
    from airframe.logs.timeline import Timeline, build_from_tag

    timeline = build_from_tag(DATA_DIR, tag)
    if not timeline.events:
        return f"no artifacts found for {tag!r}"
    if errors_only:
        context = timeline.first_error_context()
        if context:
            return _truncate(Timeline(events=context).render(limit=40))
    return _truncate(timeline.render(limit=60))


def tool_triage(tag: str, provider: str = "") -> str:
    """Run the LLM triage agent on one failure and return its verdict."""
    from airframe.triage.agent import triage_tag
    from airframe.triage.provider import get_provider

    if not (DATA_DIR / "logs" / f"{tag}.log").exists():
        return f"no artifacts for {tag!r}"
    verdict = triage_tag(tag, data_dir=DATA_DIR,
                         provider=get_provider(provider or None))
    if verdict.parse_error:
        return f"triage failed: {verdict.parse_error}"
    return _truncate(verdict.report())


def tool_cluster_failures(eps: float = 0.35) -> str:
    """Cluster corpus failures into distinct bugs."""
    from airframe.ml.cluster import cluster_failures
    from airframe.ml.features import extract_corpus

    manifest = DATA_DIR / "corpus_manifest.json"
    if not manifest.exists():
        return "no corpus; run scripts/build_corpus.py first"
    features = extract_corpus(manifest, only_failures=True)
    return _truncate(cluster_failures(features, eps=eps).report())


def tool_query_kpis(network: str = "", probe: str = "", limit: int = 30) -> str:
    """Stored network KPI measurements, with their baselines."""
    from airframe.store import db as store

    conn = store.connect()
    try:
        clauses = ["ok = 1", "value IS NOT NULL"]
        args: list[Any] = []
        if network:
            clauses.append("network = ?")
            args.append(network)
        if probe:
            clauses.append("probe = ?")
            args.append(probe)
        rows = conn.execute(
            f"""SELECT network, band, endpoint_name, probe,
                       COUNT(*) n, ROUND(AVG(value), 2) avg_value, unit
                FROM kpi_samples WHERE {' AND '.join(clauses)}
                GROUP BY network, band, endpoint_name, probe
                ORDER BY endpoint_name, probe LIMIT ?""",
            (*args, limit),
        ).fetchall()
        baselines = conn.execute(
            "SELECT scope_key, n, median, mad, unit FROM baselines ORDER BY scope_key"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return "no KPI samples stored; run `python -m airframe.kpi.runner`"
    lines = [f"{'endpoint':<20} {'probe':<14} {'n':<5} {'avg':<10} unit"]
    for row in rows:
        lines.append(
            f"{row['endpoint_name']:<20} {row['probe']:<14} {row['n']:<5} "
            f"{row['avg_value']:<10} {row['unit']}"
        )
    if baselines:
        lines.append(f"\n{len(baselines)} baseline(s):")
        for b in baselines[:20]:
            lines.append(f"  {b['scope_key']:<50} median={b['median']:.2f}{b['unit']} "
                         f"mad={b['mad']:.2f} n={b['n']}")
    return _truncate("\n".join(lines))


def tool_detect_regressions(run_id: int | None = None) -> str:
    """Compare a run's KPI samples against learned baselines."""
    from airframe.kpi.regression import detect_regressions
    from airframe.store import db as store

    conn = store.connect()
    try:
        if run_id is None:
            row = conn.execute(
                "SELECT run_id FROM kpi_samples ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return "no KPI samples stored"
            run_id = int(row["run_id"])
        findings = detect_regressions(conn, run_id)
    finally:
        conn.close()

    if not findings:
        return f"run {run_id}: no KPI samples to check"
    regressions = [f for f in findings if f.is_regression]
    lines = [f"run {run_id}: {len(regressions)} regression(s) across {len(findings)} scopes"]
    for finding in sorted(findings, key=lambda f: f.scope_key):
        if finding.is_regression or finding.verdict.value != "ok":
            lines.append(f"  {finding}")
    return _truncate("\n".join(lines))


def tool_flaky_tests(limit: int = 20) -> str:
    """Tests that pass and fail inconsistently, ranked."""
    from airframe.ml.flaky import histories_from_store
    from airframe.store import db as store

    conn = store.connect()
    try:
        histories = histories_from_store(conn)
    finally:
        conn.close()

    ranked = [h for h in histories if h.runs >= 2]
    if not ranked:
        return "not enough run history to assess flakiness (need tests seen in 2+ runs)"

    # Group by what the history actually shows. Lumping these together is the mistake
    # this tool exists to avoid: a FIXED test and a FLAKY test both look inconsistent,
    # and they call for opposite responses.
    groups: dict[str, list[Any]] = {}
    for h in ranked:
        groups.setdefault(h.classification, []).append(h)

    lines = [f"{len(ranked)} test(s) with history"]
    for label in ("flaky", "regressed", "failing", "fixed", "stable"):
        bucket = groups.get(label, [])
        if not bucket:
            continue
        bucket.sort(key=lambda h: -h.flake_rate)
        note = {
            "flaky": "  <- fix the TEST: alternates between pass and fail",
            "regressed": "  <- URGENT: was passing, now fails",
            "failing": "  <- fix the PRODUCT: fails consistently",
            "fixed": "  <- was failing, now passes (not a flake)",
            "stable": "",
        }[label]
        lines.append(f"\n{label.upper()} ({len(bucket)}){note}")
        lines.extend("  " + h.describe() for h in bucket[:limit])
    return _truncate("\n".join(lines))


def tool_list_tests(suite: str = "") -> str:
    """Collect the pytest suite without running it."""
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-store"]
    if suite:
        cmd.append(f"tests/{suite}")
    try:
        proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True,
                              text=True, timeout=120)
    except (subprocess.SubprocessError, OSError) as exc:
        return f"collection failed: {exc}"
    return _truncate(proc.stdout or proc.stderr)


def tool_run_test(node: str = "", backend: str = "sim", max_tests: int = 40) -> str:
    """Run part of the pytest suite. Gated, and simulator-only.

    Two guards, both deliberate:
      * `AIRFRAME_MCP_ALLOW_RUN` must be set, so an agent cannot execute tests unless
        a human has opted in;
      * `backend` is forced to `sim`, so nothing an agent does can touch the real
        Wi-Fi interface of the machine it is running on.
    """
    if not ALLOW_RUN:
        return ("running tests is disabled. Set AIRFRAME_MCP_ALLOW_RUN=1 in the "
                "server environment to enable it.")
    if backend != "sim":
        return "only the 'sim' backend may be driven over MCP; real hardware is refused"

    cmd = [sys.executable, "-m", "pytest", "-q", "--dut=sim",
           f"--maxfail={max_tests}", "-p", "no:cacheprovider"]
    if node:
        cmd.append(node)
    try:
        proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True,
                              text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return "test run timed out after 600s"
    except (subprocess.SubprocessError, OSError) as exc:
        return f"test run failed to start: {exc}"
    tail = (proc.stdout or "").splitlines()[-40:]
    return _truncate(f"exit={proc.returncode}\n" + "\n".join(tail))


def tool_rig_status() -> str:
    """One-shot health summary of the whole rig — the natural first call."""
    from airframe.store import db as store
    from airframe.triage.provider import get_provider

    sim = REPO_ROOT / "sim" / "build" / "airframe-sim"
    parts = [
        "AIRFRAME RIG STATUS",
        f"  simulator built : {'yes' if sim.exists() else 'NO — run cmake'}",
        f"  captures        : {len(list((DATA_DIR / 'pcaps').glob('*.pcap')))}",
        f"  logs            : {len(list((DATA_DIR / 'logs').glob('*.log')))}",
        f"  LLM provider    : {get_provider().describe()}",
        f"  test execution  : {'ENABLED' if ALLOW_RUN else 'disabled (read-only)'}",
    ]
    conn = store.connect()
    try:
        for table in ("runs", "results", "kpi_samples", "baselines", "triage_reports"):
            n = conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
            parts.append(f"  {table:<15} : {n}")
    finally:
        conn.close()
    return "\n".join(parts)


# ---------------------------------------------------------------- MCP wiring

TOOLS: dict[str, tuple[Any, str, dict[str, Any]]] = {
    "rig_status": (
        tool_rig_status,
        "Overall health of the airframe test rig: what is built, how much data exists, "
        "which LLM provider is active. Good first call.",
        {"type": "object", "properties": {}},
    ),
    "list_runs": (
        tool_list_runs,
        "List recent test runs with pass/fail counts.",
        {"type": "object", "properties": {"limit": {"type": "integer"}}},
    ),
    "get_failures": (
        tool_get_failures,
        "List failing tests for a run (defaults to the most recent run).",
        {"type": "object", "properties": {"run_id": {"type": "integer"},
                                          "limit": {"type": "integer"}}},
    ),
    "list_tests": (
        tool_list_tests,
        "Collect the pytest suite without running it. Optionally restrict to one suite "
        "directory (connectivity, interop, performance, pcap, kpi, unit).",
        {"type": "object", "properties": {"suite": {"type": "string"}}},
    ),
    "run_test": (
        tool_run_test,
        "Run pytest against the simulator. Disabled unless explicitly enabled on the "
        "server. Never touches real hardware.",
        {"type": "object", "properties": {"node": {"type": "string"},
                                          "backend": {"type": "string"},
                                          "max_tests": {"type": "integer"}}},
    ),
    "list_captures": (
        tool_list_captures,
        "List available 802.11 packet captures, optionally filtered by substring.",
        {"type": "object", "properties": {"pattern": {"type": "string"},
                                          "limit": {"type": "integer"}}},
    ),
    "analyze_pcap": (
        tool_analyze_pcap,
        "Run 802.11 forensics on a capture: reconstruct the association sequence, name "
        "where it failed, and list anomalies. detail = verdict | frames | anomalies | all",
        {"type": "object",
         "properties": {"tag": {"type": "string"},
                        "detail": {"type": "string",
                                   "enum": ["verdict", "frames", "anomalies", "all"]}},
         "required": ["tag"]},
    ),
    "get_logs": (
        tool_get_logs,
        "Fetch wireless log lines for a run, optionally filtered by substring or level.",
        {"type": "object",
         "properties": {"tag": {"type": "string"}, "contains": {"type": "string"},
                        "level": {"type": "string"}, "limit": {"type": "integer"}},
         "required": ["tag"]},
    ),
    "timeline": (
        tool_timeline,
        "Correlated timeline of log lines and packet frames on one clock. The fastest "
        "way to see the causal sequence of a failure.",
        {"type": "object",
         "properties": {"tag": {"type": "string"}, "errors_only": {"type": "boolean"}},
         "required": ["tag"]},
    ),
    "triage_failure": (
        tool_triage,
        "Run the LLM triage agent on a failure: root cause, confidence, suggested owner "
        "and a filled-in bug report.",
        {"type": "object",
         "properties": {"tag": {"type": "string"}, "provider": {"type": "string"}},
         "required": ["tag"]},
    ),
    "cluster_failures": (
        tool_cluster_failures,
        "Group all corpus failures into distinct bugs, so many red tests collapse into "
        "a few root causes.",
        {"type": "object", "properties": {"eps": {"type": "number"}}},
    ),
    "query_kpis": (
        tool_query_kpis,
        "Stored network KPI measurements and their learned baselines.",
        {"type": "object", "properties": {"network": {"type": "string"},
                                          "probe": {"type": "string"},
                                          "limit": {"type": "integer"}}},
    ),
    "detect_regressions": (
        tool_detect_regressions,
        "Check a KPI run against baselines and report regressions.",
        {"type": "object", "properties": {"run_id": {"type": "integer"}}},
    ),
    "flaky_tests": (
        tool_flaky_tests,
        "Rank tests by how inconsistently they pass, using stored run history.",
        {"type": "object", "properties": {"limit": {"type": "integer"}}},
    ),
}


def call_tool(name: str, arguments: dict[str, Any]) -> str:
    """Dispatch a tool by name. Shared by the MCP server and the CLI."""
    entry = TOOLS.get(name)
    if entry is None:
        return f"unknown tool {name!r}; available: {', '.join(sorted(TOOLS))}"
    func = entry[0]
    try:
        return str(func(**arguments))
    except TypeError as exc:
        return f"bad arguments for {name}: {exc}"
    except Exception as exc:                          # noqa: BLE001
        # Tool errors are returned as results, never raised: the agent can recover
        # from a failed tool, but an exception kills the whole session.
        return f"error in {name}: {type(exc).__name__}: {exc}"


def build_server() -> Any:
    """Construct the MCP server.

    Written against **MCP SDK 2.x**, where the class is `MCPServer` (renamed from
    `FastMCP` in 1.x) and tool schemas are derived from a function's type hints
    rather than hand-written JSON Schema. Registering the same plain functions the
    CLI uses means there is exactly one implementation of each tool and no chance of
    the two drifting apart.

    Imported lazily so `--list` and `--call` work even where the SDK is absent.
    """
    from mcp.server import MCPServer

    server = MCPServer(
        name="airframe",
        version="0.1.0",
        instructions=(
            "Wireless connectivity test rig. Start with `rig_status` to see what data "
            "exists. Use `list_captures` to find a run tag, then `analyze_pcap`, "
            "`timeline` or `triage_failure` on that tag to investigate. "
            "`cluster_failures` collapses many failures into distinct bugs. "
            "All tools are read-only except `run_test`, which is disabled by default."
        ),
    )

    for name, (func, description, _schema) in TOOLS.items():
        server.add_tool(func, name=name, description=description)
    return server


async def _serve_stdio() -> None:
    await build_server().run_stdio_async()


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="airframe MCP server")
    ap.add_argument("--list", action="store_true", help="list tools and exit")
    ap.add_argument("--call", help="invoke a tool directly (for testing)")
    ap.add_argument("--args", default="{}", help="JSON arguments for --call")
    args = ap.parse_args()

    if args.list:
        print(f"{len(TOOLS)} tools:\n")
        for name, (_f, description, schema) in TOOLS.items():
            params = ", ".join(schema.get("properties", {})) or "none"
            print(f"  {name}")
            print(f"    {description}")
            print(f"    params: {params}\n")
        return 0

    if args.call:
        print(call_tool(args.call, json.loads(args.args)))
        return 0

    import asyncio

    asyncio.run(_serve_stdio())
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
