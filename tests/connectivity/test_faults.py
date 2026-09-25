"""Fault-injection tests — the part of the suite that actually finds bugs.

Each test asserts three things, and the third is the one that matters most:

1. the connection fails (easy),
2. it fails at the **correct stage** (harder),
3. it reports the **correct IEEE code** (hardest, and the most useful).

Point 3 is what makes an automated failure actionable. "Connection failed" sends a
human to read logs; "failed in FOURWAY_HANDSHAKE with reason 15" names the
subsystem and the bug. Several faults die at the same stage and are distinguished
*only* by their code, which is exactly the discrimination the triage layer has to
reproduce — so if these assertions are weak, everything downstream inherits the
weakness.
"""

from __future__ import annotations

import pytest

from airframe.dut.base import (
    DUT,
    Capability,
    Fault,
    NetworkConfig,
    State,
)

pytestmark = [
    pytest.mark.requires_capability(Capability.FAULT_INJECTION),
    pytest.mark.requires_capability(Capability.RECONFIGURE),
]


def test_baseline_connects_without_a_fault(dut: DUT, default_network: NetworkConfig) -> None:
    """Control case. Without this, a fault test passing proves nothing."""
    assert dut.connect(default_network).ok


@pytest.mark.fault("AUTH_TIMEOUT")
def test_auth_timeout_fails_during_authentication(
    dut: DUT, default_network: NetworkConfig
) -> None:
    dut.inject_fault(Fault.AUTH_TIMEOUT)
    result = dut.connect(default_network)

    assert not result.ok
    assert result.failed_at is State.AUTHENTICATING, result.describe()
    assert result.status_name == "AUTH_TIMEOUT"
    # A supplicant that gives up in 10ms is its own bug: the timeout must elapse.
    assert result.timings.auth_ms >= 3000, (
        f"gave up after only {result.timings.auth_ms}ms; expected a real timeout"
    )
    assert result.timings.assoc_ms == 0, "must not have attempted association"


@pytest.mark.fault("ASSOC_REJECT")
def test_assoc_reject_carries_an_ieee_status_code(
    dut: DUT, default_network: NetworkConfig
) -> None:
    dut.inject_fault(Fault.ASSOC_REJECT)
    result = dut.connect(default_network)

    assert not result.ok
    assert result.failed_at is State.ASSOCIATING, result.describe()
    assert result.status_code != 0, "a rejection must carry a non-zero status code"
    assert result.timings.auth_ms > 0, "authentication should have succeeded first"


@pytest.mark.parametrize("status_code", [12, 17, 18, 45], ids=lambda c: f"status{c}")
def test_assoc_reject_reports_the_specific_status_code(
    dut: DUT, default_network: NetworkConfig, status_code: int
) -> None:
    """Different rejection reasons must be distinguishable, not lumped together."""
    dut.inject_fault(Fault.ASSOC_REJECT, code=status_code)
    result = dut.connect(default_network)

    assert not result.ok
    assert result.status_code == status_code, (
        f"expected status {status_code}, got {result.status_code} ({result.status_name})"
    )


@pytest.mark.fault("FOURWAY_M3_TIMEOUT")
def test_four_way_m3_timeout_reports_reason_15(
    dut: DUT, default_network: NetworkConfig
) -> None:
    dut.inject_fault(Fault.FOURWAY_M3_TIMEOUT)
    result = dut.connect(default_network)

    assert not result.ok
    assert result.failed_at is State.FOURWAY, result.describe()
    assert result.reason_code == 15, (
        f"IEEE reason 15 is the 4-way handshake timeout; got {result.reason_code}"
    )
    # Everything before the handshake must have succeeded, and DHCP must never
    # have been reached. The stage timings are the proof.
    assert result.timings.assoc_ms > 0
    assert result.timings.dhcp_ms == 0, "DHCP must not have been attempted"


@pytest.mark.fault("PMK_MISMATCH")
def test_pmk_mismatch_is_distinguishable_from_an_m3_timeout(
    dut: DUT, default_network: NetworkConfig
) -> None:
    """Both die in the handshake. Only the reason code tells them apart.

    This is the discrimination that makes triage possible: PMK_MISMATCH means a
    wrong passphrase (a user or provisioning problem), while an M3 timeout means
    the AP stopped responding (an infrastructure problem). Same stage, entirely
    different owner.
    """
    dut.inject_fault(Fault.PMK_MISMATCH)
    result = dut.connect(default_network)

    assert not result.ok
    assert result.failed_at is State.FOURWAY
    assert result.reason_code == 23, f"expected 802.1X failure (23), got {result.reason_code}"
    assert result.reason_code != 15, "must not be confused with an M3 timeout"


@pytest.mark.fault("DHCP_NAK")
def test_dhcp_nak_fails_after_a_fully_keyed_link(
    dut: DUT, default_network: NetworkConfig
) -> None:
    """The classic "Wi-Fi says connected but nothing works" report.

    Every radio-layer stage succeeded; only addressing failed. The stage timings
    are what prove the radio was healthy, which is how you avoid sending this bug
    to the wireless team.
    """
    dut.inject_fault(Fault.DHCP_NAK)
    result = dut.connect(default_network)

    assert not result.ok
    assert result.failed_at is State.DHCP, result.describe()
    assert not result.ip_address
    for stage in ("auth_ms", "assoc_ms", "fourway_ms"):
        assert getattr(result.timings, stage) > 0, f"{stage} should have succeeded"


@pytest.mark.fault("SCAN_EMPTY")
def test_scan_empty_fails_before_authentication(
    dut: DUT, default_network: NetworkConfig
) -> None:
    dut.inject_fault(Fault.SCAN_EMPTY)
    result = dut.connect(default_network)

    assert not result.ok
    assert result.failed_at is State.SCANNING
    assert result.timings.auth_ms == 0, "cannot authenticate to a network never found"


@pytest.mark.fault("LOW_RSSI")
def test_low_rssi_degrades_the_link_without_failing_it(
    dut: DUT, default_network: NetworkConfig
) -> None:
    """Not every fault is a hard failure.

    LOW_RSSI connects and then performs badly — a case a pass/fail-only rig cannot
    express at all, and one of the most common real complaints.
    """
    dut.inject_fault(Fault.LOW_RSSI)
    result = dut.connect(default_network)

    assert result.ok, f"LOW_RSSI should still connect: {result.describe()}"
    stats = dut.stats()
    assert stats.rssi_dbm < -80, f"expected a weak signal, got {stats.rssi_dbm} dBm"
    assert stats.link_quality == "poor"


@pytest.mark.fault("CHANNEL_BUSY")
def test_channel_busy_raises_the_retry_rate(dut: DUT, default_network: NetworkConfig) -> None:
    dut.inject_fault(Fault.CHANNEL_BUSY)
    assert dut.connect(default_network).ok
    dut.run_traffic(2000)

    stats = dut.stats()
    assert stats.retry_rate > 0.15, (
        f"a congested channel should show an elevated retry rate, got {stats.retry_rate:.1%}"
    )


@pytest.mark.fault("BEACON_LOSS")
def test_beacon_loss_drops_an_established_connection(
    dut: DUT, default_network: NetworkConfig
) -> None:
    assert dut.connect(default_network).ok
    dut.inject_fault(Fault.BEACON_LOSS)

    assert not dut.run_traffic(5000), "losing the AP should drop the link"
    assert dut.state() is not State.CONNECTED


@pytest.mark.fault("DEAUTH")
@pytest.mark.parametrize("reason_code", [1, 4, 5, 8], ids=lambda c: f"reason{c}")
def test_deauth_reports_the_injected_reason_code(
    dut: DUT, default_network: NetworkConfig, reason_code: int
) -> None:
    assert dut.connect(default_network).ok
    dut.inject_fault(Fault.DEAUTH, code=reason_code)
    assert not dut.run_traffic(5000)

    logs = "\n".join(dut.logs())
    assert f"reason={reason_code}" in logs, (
        f"reason code {reason_code} does not appear in the logs"
    )


@pytest.mark.fault("ROAM_PINGPONG")
@pytest.mark.requires_capability(Capability.ROAMING)
def test_roam_pingpong_is_reported_as_a_failure(
    dut: DUT, default_network: NetworkConfig
) -> None:
    """Ends up associated, but the user experienced four disruptions.

    "Currently connected" is not the same as "worked correctly", and a rig that
    only checks the end state would call this a pass.
    """
    assert dut.connect(default_network).ok
    dut.inject_fault(Fault.ROAM_PINGPONG)

    result = dut.roam()
    assert not result.ok, "repeated BSS transitions must be treated as a failure"
    assert result.failed_at is State.ROAMING


# ---------------------------------------------------------------- flakiness


@pytest.mark.parametrize("probability", [0.0, 1.0], ids=["never", "always"])
def test_fault_probability_boundaries_are_exact(
    dut: DUT, default_network: NetworkConfig, probability: float
) -> None:
    """0.0 must never fire and 1.0 must always fire — no off-by-one in the gate."""
    dut.inject_fault(Fault.AUTH_TIMEOUT, probability=probability)
    result = dut.connect(default_network)
    assert result.ok is (probability == 0.0)


@pytest.mark.slow
def test_probabilistic_fault_produces_a_genuine_flake(
    dut: DUT, default_network: NetworkConfig
) -> None:
    """A 50% fault must produce both outcomes across repeated attempts.

    This generates the ground truth the flaky-test predictor is trained on: the
    same configuration, both results, every individual run reproducible.
    """
    dut.inject_fault(Fault.FOURWAY_M3_TIMEOUT, probability=0.5)

    outcomes = []
    for _ in range(24):
        outcomes.append(dut.connect(default_network).ok)
        dut.reset()

    assert any(outcomes), "a 50% fault never succeeded in 24 attempts"
    assert not all(outcomes), "a 50% fault never failed in 24 attempts"
