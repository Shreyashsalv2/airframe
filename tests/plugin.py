"""The airframe pytest plugin — test infrastructure, as opposed to tests.

This file is where "SDET" actually lives. It does four jobs:

1. **Capability gating.** Skips tests whose ``@pytest.mark.requires_capability``
   the active backend cannot satisfy, with the backend named in the reason.
2. **Result persistence.** Writes every test *attempt* into SQLite via
   ``pytest_runtest_makereport``, so the ML, triage and dashboard layers have
   history to work with.
3. **Flake detection that records rather than conceals.** See below — this is the
   deliberate design decision in the file.
4. **Artifact capture.** Attaches the DUT's logs and pcap to failures.

On retries, and why this is not ``pytest-rerunfailures``
-------------------------------------------------------
The off-the-shelf plugin retries a failing test and, if a later attempt passes,
reports the test as **passed**. That makes CI green, which is why people install
it — and it is precisely the wrong behaviour. It converts a real signal
("something here is nondeterministic") into silence, and a suite that hides
flakes accumulates them until nobody trusts a red build.

This plugin retries too, because a genuinely intermittent failure should not block
a merge. The difference is in the bookkeeping:

* **every attempt** is stored as its own row, with its own outcome;
* a test that passes only after failing is marked ``is_flake = 1``;
* the terminal summary reports flakes as a separate, visible category;
* the flake rate per test is queryable (``v_flake_rate``) and feeds the
  flaky-test predictor in ``airframe/ml/flaky.py``.

The result is a green build that still tells the truth. "Passed on attempt 3" is a
different and far more actionable fact than "passed", and the whole point of test
infrastructure is to preserve that difference instead of averaging it away.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from airframe.dut.base import DUT, Capability
from airframe.store import db as store

# ---------------------------------------------------------------- shared state
#
# Keyed off the pytest config object rather than module globals so that xdist
# workers, which each import this module in their own process, cannot collide.

_STASH_RUN_ID = pytest.StashKey[int]()
_STASH_CONN = pytest.StashKey[sqlite3.Connection]()
_STASH_ATTEMPTS = pytest.StashKey[dict]()
_STASH_FLAKES = pytest.StashKey[set]()


# ---------------------------------------------------------------- options


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("airframe", "wireless test rig")
    group.addoption(
        "--dut",
        action="store",
        default=os.environ.get("AIRFRAME_DUT", "sim"),
        choices=["sim", "macos"],
        help="which device-under-test backend to run against (default: sim)",
    )
    group.addoption(
        "--seed",
        action="store",
        type=int,
        default=int(os.environ.get("AIRFRAME_SEED", "42")),
        help="RNG seed for the simulator; identical seeds reproduce byte-for-byte",
    )
    group.addoption(
        "--retries",
        action="store",
        type=int,
        default=int(os.environ.get("AIRFRAME_RETRIES", "0")),
        help="retry failing tests up to N extra times, recording every attempt",
    )
    group.addoption(
        "--artifacts",
        action="store",
        default=os.environ.get("AIRFRAME_ARTIFACTS", "data/artifacts"),
        help="directory for per-test logs and captures",
    )
    group.addoption(
        "--no-store",
        action="store_true",
        default=False,
        help="do not write results to SQLite (useful when experimenting)",
    )
    group.addoption(
        "--keep-artifacts",
        action="store_true",
        default=False,
        help="keep artifacts for passing tests too (default: failures only)",
    )


# ---------------------------------------------------------------- session


def pytest_configure(config: pytest.Config) -> None:
    config.stash[_STASH_ATTEMPTS] = {}
    config.stash[_STASH_FLAKES] = set()

    if config.getoption("--no-store"):
        return

    # xdist: only the controller opens a run row; workers attach to the same one
    # via an env var the controller sets. Without this, `-n 8` creates 8 runs.
    conn = store.connect()
    config.stash[_STASH_CONN] = conn

    existing = os.environ.get("AIRFRAME_RUN_ID")
    if existing:
        config.stash[_STASH_RUN_ID] = int(existing)
        return

    backend = config.getoption("--dut")
    run_id = store.start_run(
        conn,
        dut_backend=backend,
        seed=config.getoption("--seed") if backend == "sim" else None,
        invocation=" ".join(["pytest", *config.invocation_params.args]),
    )
    config.stash[_STASH_RUN_ID] = run_id
    os.environ["AIRFRAME_RUN_ID"] = str(run_id)


def pytest_unconfigure(config: pytest.Config) -> None:
    conn = config.stash.get(_STASH_CONN, None)
    if conn is None:
        return
    run_id = config.stash.get(_STASH_RUN_ID, None)
    if run_id is not None and not os.environ.get("PYTEST_XDIST_WORKER"):
        store.finish_run(conn, run_id)
    conn.close()


def run_id(config: pytest.Config) -> int | None:
    return config.stash.get(_STASH_RUN_ID, None)


def connection(config: pytest.Config) -> sqlite3.Connection | None:
    return config.stash.get(_STASH_CONN, None)


# ---------------------------------------------------------------- collection


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Attach capability skips and derive the suite name from the path.

    Capability checks happen **here**, at collection, not inside each test. The
    difference matters: a test skipped at collection reports as skipped with a
    reason, whereas a test that discovers mid-body that it cannot run has already
    started touching the DUT.
    """
    backend = config.getoption("--dut")
    caps = _backend_capabilities(backend)

    for item in items:
        # suite = the directory under tests/, used for grouping in the dashboard
        try:
            rel = Path(str(item.fspath)).relative_to(config.rootpath / "tests")
            item.stash[_SUITE_KEY] = rel.parts[0] if len(rel.parts) > 1 else "root"
        except (ValueError, IndexError):
            item.stash[_SUITE_KEY] = "root"

        for marker in item.iter_markers(name="requires_capability"):
            for wanted in marker.args:
                name = wanted.value if isinstance(wanted, Capability) else str(wanted)
                if name not in caps:
                    item.add_marker(
                        pytest.mark.skip(
                            reason=f"backend {backend!r} lacks capability {name!r}"
                        )
                    )


_SUITE_KEY = pytest.StashKey[str]()


def _backend_capabilities(backend: str) -> set[str]:
    """Capabilities of a backend, determined without a live DUT where possible.

    Constructing a real DUT during collection would spawn a subprocess for every
    ``--collect-only`` run, so the static answer is used for the simulator. For
    macOS the set depends on the actual hardware, so a lightweight probe is worth
    the cost — it involves no subprocess spawn of our own.
    """
    if backend == "sim":
        return {c.value for c in Capability}
    try:
        from airframe.dut.macos import MacOSDUT

        return {c.value for c in MacOSDUT().capabilities}
    except Exception:  # pragma: no cover - platform dependent
        return {Capability.REAL_TRAFFIC.value, Capability.SYSTEM_LOGS.value}


# ---------------------------------------------------------------- reporting


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    """Persist every phase outcome.

    A hook *wrapper* is required because we need the `TestReport` pytest builds,
    not just the raw `CallInfo`. `yield` hands control to pytest's own
    implementation and returns its outcome; the report is on the other side.
    """
    outcome = yield
    report: pytest.TestReport = outcome.get_result()

    config = item.config
    conn = connection(config)
    rid = run_id(config)
    if conn is None or rid is None:
        return

    # Record setup/teardown only when they actually go wrong; recording three rows
    # per passing test would triple the database for no information gain.
    if report.when != "call" and report.passed:
        return

    attempts: dict[str, int] = config.stash[_STASH_ATTEMPTS]
    attempt = attempts.get(report.nodeid, 0) + 1
    if report.when == "call":
        attempts[report.nodeid] = attempt

    verdict = _verdict(report)
    markers = {
        m.name: (m.args[0] if m.args else True)
        for m in item.iter_markers()
        if m.name not in {"parametrize", "usefixtures"}
    }
    params = dict(getattr(item, "callspec", None).params) if hasattr(item, "callspec") else {}

    artifact_dir = item.stash.get(_ARTIFACT_KEY, None)

    try:
        result_id = store.record_result(
            conn,
            run_id=rid,
            nodeid=report.nodeid,
            suite=item.stash.get(_SUITE_KEY, "root"),
            outcome=verdict,
            attempt=attempt,
            duration_s=report.duration,
            phase=report.when,
            failure_message=_one_line(report),
            failure_repr=str(report.longrepr) if report.failed else None,
            skip_reason=_skip_reason(report),
            markers={k: _plain(v) for k, v in markers.items()},
            params={k: _plain(v) for k, v in params.items()},
            artifact_dir=str(artifact_dir) if artifact_dir else None,
        )
        item.stash[_RESULT_ID_KEY] = result_id
    except sqlite3.Error:
        # Never let bookkeeping break the test run. A broken database should
        # degrade observability, not turn a passing suite red.
        pass


_ARTIFACT_KEY = pytest.StashKey[Path]()
_RESULT_ID_KEY = pytest.StashKey[int]()


def _verdict(report: pytest.TestReport) -> str:
    if report.skipped:
        return "xfailed" if hasattr(report, "wasxfail") else "skipped"
    if report.passed:
        return "xpassed" if hasattr(report, "wasxfail") else "passed"
    return "failed" if report.when == "call" else "error"


def _one_line(report: pytest.TestReport) -> str | None:
    """First meaningful line of a failure — what a bug title would say."""
    if not report.failed or report.longrepr is None:
        return None
    text = str(report.longrepr)
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("E "):
            return s[2:].strip()[:500]
    return text.splitlines()[-1][:500] if text.splitlines() else None


def _skip_reason(report: pytest.TestReport) -> str | None:
    if not report.skipped:
        return None
    if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
        return str(report.longrepr[2])[:500]
    return str(getattr(report, "wasxfail", "") or "")[:500] or None


def _plain(value: Any) -> Any:
    """Make a marker/param value JSON-serialisable without losing readability."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return getattr(value, "value", None) or str(value)


# ---------------------------------------------------------------- retries


def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None):
    """Retry failing tests, recording each attempt as its own result.

    Returning a truthy value tells pytest we have taken responsibility for running
    this item, so the default protocol is skipped. With ``--retries 0`` (the default)
    this returns ``None`` and pytest behaves exactly as normal — the retry machinery
    is entirely opt-in.

    The subtlety that bit me (see BUILD_JOURNAL.md #18): ``runtestprotocol(log=...)``
    controls whether the reports are emitted to pytest's reporting hooks. Running
    every attempt with ``log=False`` and only logging the LAST one means a test that
    passes on its first attempt is never reported at all — pytest prints
    "no tests ran". The reports must be emitted for whichever attempt we ACCEPT,
    which is not known until it has run.
    """
    retries = item.config.getoption("--retries")
    if retries <= 0:
        return None

    from _pytest.runner import runtestprotocol

    for attempt in range(retries + 1):
        is_last = attempt == retries
        # log=False everywhere: we decide what to report once we know the outcome.
        reports = runtestprotocol(item, nextitem=nextitem, log=False)
        call_report = next((r for r in reports if r.when == "call"), None)
        accepted = call_report is None or not call_report.failed or is_last

        if not accepted:
            continue

        if attempt > 0 and call_report is not None and call_report.passed:
            # Passed, but only after failing. That is the definition of a flake, and
            # it gets recorded rather than quietly celebrated.
            item.config.stash[_STASH_FLAKES].add(item.nodeid)
            conn = connection(item.config)
            rid = run_id(item.config)
            if conn is not None and rid is not None:
                try:
                    store.mark_flake(conn, rid, item.nodeid)
                except sqlite3.Error:
                    pass
            # Annotate the report so the terminal shows WHY it is green.
            for report in reports:
                if report.when == "call":
                    report.sections.append(
                        ("airframe", f"passed on attempt {attempt + 1} of {retries + 1} "
                                     "— recorded as a FLAKE")
                    )

        # Emit the accepted attempt's reports so pytest counts and prints the test.
        for report in reports:
            item.ihook.pytest_runtest_logreport(report=report)
        break

    return True


# ---------------------------------------------------------------- artifacts


def attach_artifact_dir(item: pytest.Item, path: Path) -> None:
    """Called by the ``dut`` fixture so failures know where their evidence is."""
    item.stash[_ARTIFACT_KEY] = path


def record_dut_artifacts(item: pytest.Item, dut: DUT) -> None:
    """Persist logs and captures, and register them in the store."""
    conn = connection(item.config)
    rid = run_id(item.config)
    path = item.stash.get(_ARTIFACT_KEY, None)
    if conn is None or rid is None or path is None:
        return

    result_id = item.stash.get(_RESULT_ID_KEY, None)
    try:
        log_lines = dut.logs()
        if log_lines:
            log_file = path / "dut.log"
            log_file.write_text("\n".join(log_lines) + "\n")
            store.record_artifact(
                conn, kind="log", path=log_file, run_id=rid, result_id=result_id
            )
        pcap = dut.capture_path()
        if pcap and Path(pcap).exists():
            dest = path / "capture.pcap"
            if Path(pcap).resolve() != dest.resolve():
                shutil.copy2(pcap, dest)
            store.record_artifact(
                conn, kind="pcap", path=dest, run_id=rid, result_id=result_id
            )
    except (OSError, sqlite3.Error):
        pass


# ---------------------------------------------------------------- summary


def pytest_terminal_summary(
    terminalreporter: Any, exitstatus: int, config: pytest.Config
) -> None:
    """Report flakes as their own category, and point at the stored run."""
    flakes: set[str] = config.stash.get(_STASH_FLAKES, set())
    rid = run_id(config)

    if flakes:
        terminalreporter.write_sep("=", "FLAKY TESTS (passed only after retrying)", yellow=True)
        for nodeid in sorted(flakes):
            terminalreporter.write_line(f"  FLAKE {nodeid}")
        terminalreporter.write_line(
            "\n  These are recorded as flakes in the result store, not as passes."
        )

    if rid is not None:
        terminalreporter.write_line(
            f"\nairframe: backend={config.getoption('--dut')} run_id={rid} "
            f"db={store.db_path()}"
        )
