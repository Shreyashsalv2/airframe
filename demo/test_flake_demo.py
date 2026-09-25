"""A deliberately flaky test, to demonstrate that flakes are RECORDED not hidden.

This is the counter-demonstration to `pytest-rerunfailures`, which reports a test
that passed on retry as simply "passed". Here the same test goes green — so CI is not
blocked — but the result store keeps every attempt and marks the test as a flake, the
terminal summary lists it under its own heading, and `v_flake_rate` ranks it.

Run:  pytest demo --retries=3 -q
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

STATE = Path("/tmp/airframe_flake_demo_state")


@pytest.fixture(autouse=True)
def _reset_state():
    # Fail the first two attempts, pass the third. Deterministic, so the demo is
    # reproducible rather than genuinely random — the point is the bookkeeping, and a
    # demo that sometimes does not flake would not demonstrate anything.
    yield


def test_flaky_connection_recorded_as_flake() -> None:
    """Fails twice, then passes — the canonical flake shape."""
    attempt = int(STATE.read_text()) + 1 if STATE.exists() else 1
    STATE.write_text(str(attempt))
    if attempt < 3:
        pytest.fail(f"simulated intermittent failure (attempt {attempt} of 3)")
    STATE.unlink(missing_ok=True)


def test_always_passes() -> None:
    """Control case: a stable test must not be marked as a flake."""
    assert True


def test_always_fails() -> None:
    """Control case: a consistently failing test is a FAILURE, not a flake.

    This is the distinction that matters. Retrying must not turn a real regression
    green, and it must not mislabel one as flaky.
    """
    if os.environ.get("AIRFRAME_DEMO_INCLUDE_FAILING") != "1":
        pytest.skip("set AIRFRAME_DEMO_INCLUDE_FAILING=1 to include the failing control")
    pytest.fail("this test fails every time — a genuine regression, not a flake")
