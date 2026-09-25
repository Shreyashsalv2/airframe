"""End-to-end regression detection: store -> baselines -> verdict.

The unit tests in `tests/kpi/` exercise `check_value()` against hand-built `Baseline`
objects. These go through the real path — record samples, learn baselines from them,
then judge a new measurement — because that path has three places to get it wrong that
a unit test cannot see: the scope key must match between write and read, the baseline
must actually persist, and the samples must be filtered to the right scope.

Also pins BUILD_JOURNAL.md #14: a 9x throughput collapse against a genuinely noisy
baseline must still be CRITICAL, because the z-score alone cannot see it.
"""

from __future__ import annotations

import pytest

from airframe.kpi.regression import (
    Verdict,
    detect_regressions,
    load_baseline,
    rebuild_baselines,
    scope_key,
)
from airframe.store import db as store

NETWORK, BAND = "testnet", "5GHz"


@pytest.fixture
def seeded_db(tmp_path):
    """A store with enough history to learn baselines from."""
    conn = store.connect(tmp_path / "reg.db")

    # Tight metric: latency around 20ms with small variation.
    rid = store.start_run(conn, dut_backend="macos")
    for value in [20, 21, 19, 22, 20, 21, 20, 19, 23, 20, 21, 20]:
        store.record_kpi(conn, run_id=rid, network=NETWORK, band=BAND,
                         endpoint_name="dns_ep", probe="dns", value=float(value),
                         unit="ms")
    # Noisy metric: throughput with ~50% relative MAD, as measured in the real world.
    for value in [36, 70, 18, 45, 22, 88, 30, 55, 12, 40, 62, 25]:
        store.record_kpi(conn, run_id=rid, network=NETWORK, band=BAND,
                         endpoint_name="cdn_ep", probe="throughput", value=float(value),
                         unit="mbps")
    rebuild_baselines(conn)
    yield conn
    conn.close()


class TestBaselineLearning:
    def test_baselines_are_persisted_and_readable(self, seeded_db) -> None:
        baseline = load_baseline(seeded_db, scope_key(NETWORK, BAND, "dns_ep", "dns"))
        assert baseline is not None
        assert 19 <= baseline.median <= 22
        assert baseline.n >= 8

    def test_scope_key_round_trips_between_write_and_read(self, seeded_db) -> None:
        """A mismatch here silently means every measurement has 'no baseline'."""
        assert load_baseline(seeded_db, scope_key(NETWORK, BAND, "cdn_ep",
                                                  "throughput")) is not None
        assert load_baseline(seeded_db, scope_key(NETWORK, "2.4GHz", "cdn_ep",
                                                  "throughput")) is None

    def test_noisy_metric_is_identified_as_noisy(self, seeded_db) -> None:
        baseline = load_baseline(seeded_db,
                                 scope_key(NETWORK, BAND, "cdn_ep", "throughput"))
        assert baseline is not None
        assert baseline.is_noisy, f"relative MAD was {baseline.relative_mad:.2f}"

    def test_tight_metric_is_not_noisy(self, seeded_db) -> None:
        baseline = load_baseline(seeded_db, scope_key(NETWORK, BAND, "dns_ep", "dns"))
        assert baseline is not None
        assert not baseline.is_noisy


class TestEndToEndDetection:
    def _judge(self, conn, endpoint: str, probe: str, value: float, unit: str):
        rid = store.start_run(conn, dut_backend="macos")
        store.record_kpi(conn, run_id=rid, network=NETWORK, band=BAND,
                         endpoint_name=endpoint, probe=probe, value=value, unit=unit)
        findings = detect_regressions(conn, rid)
        assert findings, "the new sample was not picked up"
        return findings[0]

    def test_a_normal_measurement_passes(self, seeded_db) -> None:
        assert not self._judge(seeded_db, "dns_ep", "dns", 21.0, "ms").is_regression

    def test_a_clear_latency_regression_is_caught(self, seeded_db) -> None:
        finding = self._judge(seeded_db, "dns_ep", "dns", 400.0, "ms")
        assert finding.is_regression
        assert finding.verdict is Verdict.CRITICAL

    def test_a_latency_improvement_is_not_a_regression(self, seeded_db) -> None:
        """A two-sided test would report getting faster as a failure."""
        assert not self._judge(seeded_db, "dns_ep", "dns", 4.0, "ms").is_regression

    def test_throughput_collapse_is_caught_despite_a_noisy_baseline(self, seeded_db) -> None:
        """BUILD_JOURNAL.md #14, pinned end to end.

        Against a baseline with ~50% relative MAD the z-score for a 9x collapse is
        about -1.2 — nowhere near any sane threshold. Only the ratio test sees it.
        """
        finding = self._judge(seeded_db, "cdn_ep", "throughput", 4.0, "mbps")
        assert finding.is_regression, (
            f"a 9x throughput collapse was missed (z={finding.z_score:.2f})"
        )
        assert finding.verdict is Verdict.CRITICAL
        assert abs(finding.z_score) < 3.5, (
            "this test is only meaningful while the z-score alone would miss it"
        )

    def test_throughput_improvement_is_not_a_regression(self, seeded_db) -> None:
        finding = self._judge(seeded_db, "cdn_ep", "throughput", 200.0, "mbps")
        assert not finding.is_regression

    def test_an_unknown_scope_reports_no_baseline_not_a_pass(self, seeded_db) -> None:
        """Silence must not be mistaken for approval."""
        finding = self._judge(seeded_db, "brand_new_ep", "dns", 9999.0, "ms")
        assert finding.verdict is Verdict.NO_BASELINE
        assert not finding.is_regression

    def test_a_run_with_no_kpi_samples_returns_nothing(self, seeded_db) -> None:
        rid = store.start_run(seeded_db, dut_backend="sim")
        assert detect_regressions(seeded_db, rid) == []
