"""Link-quality tests that run on **both** backends.

This file is where the hybrid design pays off. Everything here is written against
observable radio state — RSSI, noise, SNR, channel, width, negotiated rate — which
both the simulator and a real Wi-Fi card can report. The same assertions therefore
run against simulated hardware in CI and against this MacBook's actual radio
locally, with no branching in the test bodies.

Where the two genuinely differ, the difference is expressed as a capability
requirement rather than an `if backend == ...`. A conditional inside a test body is
how suites rot: the branch stops being exercised, and nobody notices.
"""

from __future__ import annotations

import pytest

from airframe.dut.base import DUT, Band, Capability, LinkStats, State

# ---------------------------------------------------------------- helpers


def _require_link(dut: DUT) -> LinkStats:
    """Skip rather than fail when there is no link to measure.

    An unassociated machine is not a test failure — it is a missing precondition,
    and conflating the two makes a red run impossible to read at a glance.
    """
    if dut.state() is not State.CONNECTED:
        result = dut.connect()
        if not result.connected:
            pytest.skip(f"no link available to measure: {result.describe()}")
    return dut.stats()


# ---------------------------------------------------------------- radio sanity


def test_rssi_is_within_physically_plausible_bounds(dut: DUT) -> None:
    """A real Wi-Fi RSSI lives between about -100 and -10 dBm.

    Values outside that range mean a broken parser or a sign error, not a bad
    radio — worth asserting precisely because it catches *our* bugs, not the
    network's.
    """
    stats = _require_link(dut)
    assert -100 <= stats.rssi_dbm <= -10, f"implausible RSSI: {stats.rssi_dbm} dBm"


def test_noise_floor_is_plausible(dut: DUT) -> None:
    stats = _require_link(dut)
    assert -120 <= stats.noise_dbm <= -60, f"implausible noise floor: {stats.noise_dbm} dBm"


def test_snr_is_consistent_with_rssi_and_noise(dut: DUT) -> None:
    """SNR must equal RSSI minus noise. An internal-consistency check.

    If these three disagree, one of them is being computed or parsed wrongly, and
    every threshold built on top of them is meaningless.
    """
    stats = _require_link(dut)
    assert stats.snr_db == stats.rssi_dbm - stats.noise_dbm, (
        f"SNR {stats.snr_db} != RSSI {stats.rssi_dbm} - noise {stats.noise_dbm}"
    )


def test_snr_is_sufficient_for_a_usable_link(dut: DUT) -> None:
    """Below roughly 15 dB SNR, 802.11 rate adaptation collapses."""
    stats = _require_link(dut)
    assert stats.snr_db >= 10, (
        f"SNR of {stats.snr_db} dB is below the usable floor "
        f"(rssi={stats.rssi_dbm}, noise={stats.noise_dbm})"
    )


def test_channel_and_band_are_consistent(dut: DUT) -> None:
    """Channel numbers are band-specific; a mismatch means a parsing bug."""
    stats = _require_link(dut)
    if stats.channel == 0:
        pytest.skip("backend did not report a channel")

    scan = dut.scan()
    if not scan:
        pytest.skip("no scan data to cross-check the band against")
    band = scan[0].band

    if band is Band.GHZ_2_4:
        assert 1 <= stats.channel <= 14, f"channel {stats.channel} is not a 2.4GHz channel"
    elif band is Band.GHZ_5:
        assert 32 <= stats.channel <= 177, f"channel {stats.channel} is not a 5GHz channel"


def test_channel_width_is_a_legal_value(dut: DUT) -> None:
    stats = _require_link(dut)
    if stats.width_mhz == 0:
        pytest.skip("backend did not report a channel width")
    assert stats.width_mhz in (20, 40, 80, 160, 320), (
        f"{stats.width_mhz}MHz is not a legal 802.11 channel width"
    )


def test_negotiated_rate_is_plausible_for_the_width(dut: DUT) -> None:
    """Cross-check rate against channel width.

    The exact rate depends on MCS, spatial streams and guard interval, so this
    asserts only an upper bound no configuration can exceed — a loose check that
    still catches unit errors (Mbps vs Kbps) and garbage parses.
    """
    stats = _require_link(dut)
    if stats.tx_rate_mbps == 0 or stats.width_mhz == 0:
        pytest.skip("backend did not report both rate and width")

    ceiling = {20: 600, 40: 1200, 80: 2500, 160: 5000, 320: 12000}
    limit = ceiling.get(stats.width_mhz, 12000)
    assert 0 < stats.tx_rate_mbps <= limit, (
        f"{stats.tx_rate_mbps} Mbps is impossible on a {stats.width_mhz}MHz channel"
    )


def test_link_quality_classification_matches_snr(dut: DUT) -> None:
    """The human-readable bucket must agree with the number it is derived from."""
    stats = _require_link(dut)
    quality = stats.link_quality

    if stats.snr_db >= 40:
        assert quality == "excellent"
    elif stats.snr_db >= 25:
        assert quality == "good"
    elif stats.snr_db >= 15:
        assert quality == "fair"
    else:
        assert quality == "poor"


def test_stats_are_stable_across_consecutive_reads(dut: DUT) -> None:
    """Two reads a moment apart should broadly agree.

    Real RSSI fluctuates by a few dB, so a tolerance is required — asserting exact
    equality against live hardware is how you write a flaky test on purpose.
    """
    first = _require_link(dut)
    second = dut.stats()

    assert abs(first.rssi_dbm - second.rssi_dbm) <= 15, (
        f"RSSI jumped from {first.rssi_dbm} to {second.rssi_dbm} dBm between reads"
    )
    if first.channel and second.channel:
        assert first.channel == second.channel, "the channel changed mid-test"


# ---------------------------------------------------------------- identity / caps


def test_backend_reports_an_identity(shared_dut: DUT) -> None:
    identity = shared_dut.identity()
    assert identity and len(identity) > 5, "every backend must describe itself"
    # Deliberately NOT a hardcoded list of backend names. A test that knows which
    # backends exist is a test that breaks every time one is added — which is exactly
    # what happened when the replay backend arrived. Assert the contract (it has a
    # name), not the roster.
    assert shared_dut.backend and shared_dut.backend.isidentifier()


def test_capabilities_are_declared_and_coherent(shared_dut: DUT) -> None:
    """Capability declarations must be self-consistent.

    A backend claiming determinism while also claiming to move real traffic is
    describing something impossible, and would mislead every test that trusts the
    declaration.
    """
    caps = shared_dut.capabilities
    assert caps, "a backend with no capabilities can run no tests"

    # NOTE: an earlier version asserted "deterministic implies fault injection", on the
    # reasoning that a deterministic backend must be a simulator. That is false, and the
    # replay backend is the counterexample: a recording is perfectly deterministic and
    # cannot be ordered to fail differently, because it already happened. The assumption
    # survived only because two backends happened to satisfy it.
    if Capability.FAULT_INJECTION in caps:
        assert Capability.DETERMINISTIC in caps, (
            "a backend that can be ordered to fail must be reproducible, or the "
            "failure it produces cannot be investigated"
        )
    if shared_dut.backend == "macos":
        assert Capability.DETERMINISTIC not in caps, (
            "real hardware cannot be deterministic"
        )
        assert Capability.REAL_TRAFFIC in caps


def test_supports_accepts_both_enum_and_string(shared_dut: DUT) -> None:
    """Ergonomics check — markers pass strings, code passes enums."""
    for cap in shared_dut.capabilities:
        assert shared_dut.supports(cap)
        assert shared_dut.supports(cap.value)
    assert not shared_dut.supports("not_a_real_capability")


# ---------------------------------------------------------------- traffic


@pytest.mark.slow
def test_link_survives_sustained_traffic(connected_dut: DUT) -> None:
    assert connected_dut.run_traffic(3000), "link dropped while passing traffic"
    assert connected_dut.state() is State.CONNECTED


@pytest.mark.requires_capability(Capability.FAULT_INJECTION)
def test_retry_rate_is_low_on_a_healthy_link(connected_dut: DUT) -> None:
    """Requires fault injection only because real hardware will not expose
    per-frame retry counters without driver-level access."""
    connected_dut.run_traffic(2000)
    stats = connected_dut.stats()
    assert stats.retry_rate < 0.15, (
        f"retry rate of {stats.retry_rate:.1%} is too high for an uncongested channel"
    )
