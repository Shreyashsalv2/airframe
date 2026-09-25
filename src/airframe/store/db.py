"""SQLite result store — the shared contract between every layer of airframe.

The pytest plugin writes here; the ML, triage, dashboard and MCP layers read from here.
Plain `sqlite3` and hand-written SQL on purpose (see schema.sql for the reasoning).

Design notes worth knowing:

* `PRAGMA foreign_keys` is **per connection** in SQLite, not per database. Forgetting to
  set it on every new connection is the single most common SQLite mistake — your cascades
  silently do nothing and orphaned rows accumulate. `connect()` sets it every time.
* `row_factory = sqlite3.Row` so rows behave like mappings (`row["outcome"]`) instead of
  positional tuples, which keeps call sites readable when the schema changes.
* Timestamps are ISO-8601 UTC strings. Sortable lexicographically, greppable in a shell,
  and unambiguous across timezones.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Repo root = three parents up from src/airframe/store/db.py
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB = REPO_ROOT / "data" / "db" / "airframe.db"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def utcnow() -> str:
    """ISO-8601 UTC timestamp, seconds precision, no microsecond noise in logs."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def db_path() -> Path:
    """Resolve the database path, honouring AIRFRAME_DB for tests and CI."""
    env = os.environ.get("AIRFRAME_DB")
    return Path(env).expanduser().resolve() if env else DEFAULT_DB


# ---------------------------------------------------------------- connection


def connect(path: Path | str | None = None, *, init: bool = True) -> sqlite3.Connection:
    """Open a connection with the pragmas and row factory airframe expects."""
    target = Path(path) if path is not None else db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    fresh = not target.exists()

    conn = sqlite3.connect(target, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Per-connection pragmas. foreign_keys in particular defaults to OFF.
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    except sqlite3.OperationalError:
        pass  # WAL is unavailable on some network filesystems; not fatal.

    if init and (fresh or not _has_tables(conn)):
        init_schema(conn)
    return conn


def _has_tables(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table' AND name='runs'"
    ).fetchone()
    return bool(row and row["n"])


def init_schema(conn: sqlite3.Connection) -> None:
    """Apply schema.sql. Idempotent — every statement is CREATE ... IF NOT EXISTS."""
    conn.executescript(SCHEMA_PATH.read_text())


@contextmanager
def session(path: Path | str | None = None) -> Iterator[sqlite3.Connection]:
    """Context-managed connection that always closes, even on exception."""
    conn = connect(path)
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------- helpers


def _j(value: Any) -> str | None:
    """JSON-encode for a *_json column, or None so the column stays NULL."""
    if value is None:
        return None
    return json.dumps(value, default=str, sort_keys=True)


def git_sha() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def env_snapshot() -> dict[str, Any]:
    """Capture enough of the environment to explain a result months later."""
    import platform

    def tool_version(cmd: list[str]) -> str | None:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return (out.stdout or out.stderr).splitlines()[0].strip() or None
        except (OSError, subprocess.SubprocessError, IndexError):
            return None

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "tshark": tool_version(["tshark", "--version"]),
        "iperf3": tool_version(["iperf3", "--version"]),
    }


# ---------------------------------------------------------------- runs


def start_run(
    conn: sqlite3.Connection,
    *,
    dut_backend: str,
    dut_identity: str | None = None,
    seed: int | None = None,
    invocation: str | None = None,
    notes: str | None = None,
) -> int:
    cur = conn.execute(
        """INSERT INTO runs (started_at, dut_backend, dut_identity, seed, git_sha,
                             invocation, env_json, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            utcnow(),
            dut_backend,
            dut_identity,
            seed,
            git_sha(),
            invocation or " ".join(sys.argv),
            _j(env_snapshot()),
            notes,
        ),
    )
    return int(cur.lastrowid)


def finish_run(conn: sqlite3.Connection, run_id: int, exit_status: int | None = None) -> None:
    conn.execute(
        "UPDATE runs SET finished_at = ?, exit_status = ? WHERE id = ?",
        (utcnow(), exit_status, run_id),
    )


# ---------------------------------------------------------------- results


def record_result(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    nodeid: str,
    outcome: str,
    attempt: int = 1,
    total_attempts: int = 1,
    is_flake: bool = False,
    duration_s: float | None = None,
    phase: str | None = None,
    suite: str | None = None,
    failure_message: str | None = None,
    failure_repr: str | None = None,
    skip_reason: str | None = None,
    markers: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    artifact_dir: str | None = None,
    started_at: str | None = None,
) -> int:
    """Insert one test *attempt*. Retries insert new rows; nothing is overwritten."""
    cur = conn.execute(
        """INSERT INTO results (run_id, nodeid, suite, outcome, attempt, total_attempts,
                                is_flake, duration_s, phase, failure_message, failure_repr,
                                skip_reason, markers_json, params_json, artifact_dir, started_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(run_id, nodeid, attempt) DO UPDATE SET
               outcome         = excluded.outcome,
               is_flake        = excluded.is_flake,
               duration_s      = excluded.duration_s,
               phase           = excluded.phase,
               failure_message = excluded.failure_message,
               failure_repr    = excluded.failure_repr,
               skip_reason      = excluded.skip_reason,
               total_attempts  = excluded.total_attempts""",
        (
            run_id,
            nodeid,
            suite,
            outcome,
            attempt,
            total_attempts,
            int(is_flake),
            duration_s,
            phase,
            failure_message,
            failure_repr,
            skip_reason,
            _j(markers),
            _j(params),
            artifact_dir,
            started_at or utcnow(),
        ),
    )
    if cur.lastrowid:
        return int(cur.lastrowid)
    row = conn.execute(
        "SELECT id FROM results WHERE run_id=? AND nodeid=? AND attempt=?",
        (run_id, nodeid, attempt),
    ).fetchone()
    return int(row["id"])


def mark_flake(conn: sqlite3.Connection, run_id: int, nodeid: str) -> None:
    """Flag every attempt of a test that eventually passed after failing."""
    conn.execute(
        "UPDATE results SET is_flake = 1 WHERE run_id = ? AND nodeid = ?",
        (run_id, nodeid),
    )


def failed_results(conn: sqlite3.Connection, run_id: int | None = None) -> list[sqlite3.Row]:
    sql = "SELECT * FROM v_final_results WHERE outcome IN ('failed','error')"
    args: tuple[Any, ...] = ()
    if run_id is not None:
        sql += " AND run_id = ?"
        args = (run_id,)
    return list(conn.execute(sql + " ORDER BY id", args))


def latest_run_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    return int(row["id"]) if row else None


# ---------------------------------------------------------------- KPI


def record_kpi(
    conn: sqlite3.Connection,
    *,
    endpoint_name: str,
    probe: str,
    unit: str,
    value: float | None = None,
    run_id: int | None = None,
    result_id: int | None = None,
    network: str | None = None,
    band: str | None = None,
    endpoint_host: str | None = None,
    ok: bool = True,
    error: str | None = None,
    ts: str | None = None,
) -> int:
    cur = conn.execute(
        """INSERT INTO kpi_samples (run_id, result_id, ts, network, band, endpoint_name,
                                    endpoint_host, probe, value, unit, ok, error)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            run_id,
            result_id,
            ts or utcnow(),
            network,
            band,
            endpoint_name,
            endpoint_host,
            probe,
            value,
            unit,
            int(ok),
            error,
        ),
    )
    return int(cur.lastrowid)


def kpi_values(
    conn: sqlite3.Connection,
    *,
    network: str | None = None,
    band: str | None = None,
    endpoint_name: str | None = None,
    probe: str | None = None,
    limit: int | None = None,
) -> list[float]:
    """Successful KPI values matching a scope, newest last."""
    clauses = ["ok = 1", "value IS NOT NULL"]
    args: list[Any] = []
    for col, val in (
        ("network", network),
        ("band", band),
        ("endpoint_name", endpoint_name),
        ("probe", probe),
    ):
        if val is not None:
            clauses.append(f"{col} = ?")
            args.append(val)
    sql = f"SELECT value FROM kpi_samples WHERE {' AND '.join(clauses)} ORDER BY id"
    if limit:
        # Newest N, then restore chronological order.
        sql = (
            f"SELECT value FROM (SELECT id, value FROM kpi_samples "
            f"WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT {int(limit)}) ORDER BY id"
        )
    return [float(r["value"]) for r in conn.execute(sql, args)]


def upsert_baseline(
    conn: sqlite3.Connection,
    *,
    scope_key: str,
    n: int,
    median: float,
    mad: float,
    p95: float | None = None,
    p99: float | None = None,
    min_value: float | None = None,
    max_value: float | None = None,
    unit: str | None = None,
) -> None:
    conn.execute(
        """INSERT INTO baselines (scope_key, n, median, mad, p95, p99, min_value,
                                  max_value, unit, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(scope_key) DO UPDATE SET
               n=excluded.n, median=excluded.median, mad=excluded.mad, p95=excluded.p95,
               p99=excluded.p99, min_value=excluded.min_value, max_value=excluded.max_value,
               unit=excluded.unit, updated_at=excluded.updated_at""",
        (scope_key, n, median, mad, p95, p99, min_value, max_value, unit, utcnow()),
    )


def get_baseline(conn: sqlite3.Connection, scope_key: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM baselines WHERE scope_key = ?", (scope_key,)).fetchone()


# ---------------------------------------------------------------- logs


def upsert_template(conn: sqlite3.Connection, template: str, param_count: int = 0) -> int:
    conn.execute(
        """INSERT INTO log_templates (template, param_count, hit_count, first_seen, last_seen)
           VALUES (?, ?, 1, ?, ?)
           ON CONFLICT(template) DO UPDATE SET
               hit_count = hit_count + 1, last_seen = excluded.last_seen""",
        (template, param_count, utcnow(), utcnow()),
    )
    row = conn.execute("SELECT id FROM log_templates WHERE template = ?", (template,)).fetchone()
    return int(row["id"])


def record_log_lines(conn: sqlite3.Connection, rows: Iterable[dict[str, Any]]) -> int:
    """Bulk-insert parsed log lines. Returns the count inserted."""
    payload = [
        (
            r.get("run_id"),
            r.get("result_id"),
            r.get("template_id"),
            r.get("ts"),
            r.get("monotonic_ms"),
            r.get("level"),
            r.get("component"),
            r["message"],
            _j(r.get("params")),
            r.get("raw"),
        )
        for r in rows
    ]
    if not payload:
        return 0
    conn.executemany(
        """INSERT INTO log_lines (run_id, result_id, template_id, ts, monotonic_ms, level,
                                  component, message, params_json, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        payload,
    )
    return len(payload)


# ---------------------------------------------------------------- clusters & triage


def record_cluster(
    conn: sqlite3.Connection,
    *,
    run_id: int | None,
    label: int,
    size: int,
    signature: str,
    exemplar_result_id: int | None,
    member_ids: Iterable[int] = (),
) -> int:
    cur = conn.execute(
        """INSERT INTO failure_clusters (run_id, label, size, signature,
                                         exemplar_result_id, created_at)
           VALUES (?,?,?,?,?,?)""",
        (run_id, label, size, signature, exemplar_result_id, utcnow()),
    )
    cid = int(cur.lastrowid)
    members = [(cid, int(rid), None) for rid in member_ids]
    if members:
        conn.executemany(
            "INSERT OR IGNORE INTO cluster_members (cluster_id, result_id, distance) VALUES (?,?,?)",
            members,
        )
    return cid


def record_triage(
    conn: sqlite3.Connection,
    *,
    result_id: int,
    provider: str,
    run_id: int | None = None,
    model: str | None = None,
    root_cause: str | None = None,
    confidence: float | None = None,
    suggested_owner: str | None = None,
    evidence: list[str] | None = None,
    bug_report_md: str | None = None,
    tool_calls: int = 0,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    latency_s: float | None = None,
) -> int:
    cur = conn.execute(
        """INSERT INTO triage_reports (result_id, run_id, provider, model, root_cause,
                                       confidence, suggested_owner, evidence_json,
                                       bug_report_md, tool_calls, tokens_in, tokens_out,
                                       latency_s, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            result_id,
            run_id,
            provider,
            model,
            root_cause,
            confidence,
            suggested_owner,
            _j(evidence),
            bug_report_md,
            tool_calls,
            tokens_in,
            tokens_out,
            latency_s,
            utcnow(),
        ),
    )
    return int(cur.lastrowid)


def record_artifact(
    conn: sqlite3.Connection,
    *,
    kind: str,
    path: str | Path,
    run_id: int | None = None,
    result_id: int | None = None,
) -> int:
    import hashlib

    p = Path(path)
    size = p.stat().st_size if p.exists() else None
    digest = None
    if p.exists() and p.is_file() and (size or 0) < 64 * 1024 * 1024:
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
    cur = conn.execute(
        """INSERT INTO artifacts (run_id, result_id, kind, path, bytes, sha256, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (run_id, result_id, kind, str(p), size, digest, utcnow()),
    )
    return int(cur.lastrowid)


# ---------------------------------------------------------------- CLI


def _main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="airframe.store.db", description="airframe result store")
    ap.add_argument("--init", action="store_true", help="create the database and schema")
    ap.add_argument("--path", help="database path (default: data/db/airframe.db)")
    ap.add_argument("--stats", action="store_true", help="summarise stored data")
    ap.add_argument("--reset", action="store_true", help="delete and recreate the database")
    args = ap.parse_args(argv)

    target = Path(args.path) if args.path else db_path()

    if args.reset and target.exists():
        for suffix in ("", "-wal", "-shm"):
            q = Path(str(target) + suffix)
            if q.exists():
                q.unlink()
        print(f"removed {target}")

    conn = connect(target)
    try:
        if args.init or args.reset:
            init_schema(conn)
            tables = [
                r["name"]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            ]
            views = [
                r["name"]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
                )
            ]
            print(f"initialised {target}")
            print(f"  tables ({len(tables)}): {', '.join(tables)}")
            print(f"  views  ({len(views)}): {', '.join(views)}")

        if args.stats:
            print(f"\n{target}")
            for table in (
                "runs",
                "results",
                "kpi_samples",
                "baselines",
                "log_lines",
                "log_templates",
                "failure_clusters",
                "triage_reports",
                "artifacts",
            ):
                n = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
                print(f"  {table:<18} {n:>8}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
