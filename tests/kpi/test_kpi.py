"""Tests for the KPI layer.

Split into three groups by what they need:

* **statistics** — pure functions, no network. These are the tests that pin down the
  robust-statistics reasoning, and they run everywhere.
* **regression logic** — a temporary database, synthetic samples, no network.
* **live probes** — marked ``network``, deselected in CI with ``-m "not network"``.

That split matters: the parts of a KPI suite worth testing hardest are the ones that
*interpret* measurements, and those need no network at all. A suite that can only be
tested with live internet is a suite that will not be tested.
"""

from __future__ import annotations

import math

import pytest

from airframe.kpi import stats
from airframe.kpi.endpoints import ENDPOINTS, EndpointRole, by_name, by_role, resolve_gateway
from airframe.kpi.regression import (
    CRITICAL_RATIO,
    MIN_BASELINE_SAMPLES,
    SEVERE_RATIO,
    Baseline,
    Verdict,
    check_value,
    compute_baseline,
    load_baseline,
    rebuild_baselines,
    save_baseline,
    scope_key,
)
from airframe.store import db as store

# ---------------------------------------------------------------- statistics


class TestRobustStatistics:
    """The heart of the KPI layer's correctness."""

    def test_percentile_interpolates(self) -> None:
        values = [1, 2, 3, 4, 5]
        assert stats.percentile(values, 0) == 1
        assert stats.percentile(values, 50) == 3
        assert stats.percentile(values, 100) == 5
        assert stats.percentile(values, 25) == 2

    def test_percentile_of_empty_is_nan_not_an_exception(self) -> None:
        """A missing measurement must not crash a report."""
        assert math.isnan(stats.percentile([], 50))
        assert math.isnan(stats.median([]))
        assert math.isnan(stats.mad([]))

    def test_median_resists_an_outlier_and_mean_does_not(self) -> None:
        """The single most important property in this module.

        A real 2000ms stall in otherwise-20ms data must not move the baseline.
        """
        clean = [20, 21, 19, 22, 20]
        with_outlier = [*clean, 2000]

        assert abs(stats.median(clean) - stats.median(with_outlier)) <= 1.0, (
            "median must barely move"
        )
        mean_clean = sum(clean) / len(clean)
        mean_dirty = sum(with_outlier) / len(with_outlier)
        assert mean_dirty > mean_clean * 10, "the mean is destroyed by one outlier"

    def test_mad_resists_an_outlier_and_stddev_does_not(self) -> None:
        clean = stats.summarise([20, 21, 19, 22, 20])
        dirty = stats.summarise([20, 21, 19, 22, 20, 2000])

        assert dirty.mad <= clean.mad * 3, "MAD should stay in the same ballpark"
        assert dirty.stddev > clean.stddev * 100, "stddev is destroyed"

    def test_classic_threshold_fails_where_robust_one_works(self) -> None:
        """The concrete demonstration that motivates the whole design.

        With mean+3sigma, the outlier raises the alert threshold ABOVE the failure it
        was meant to detect. This test documents that failure mode permanently.
        """
        samples = [20, 21, 19, 22, 20, 2000]
        s = stats.summarise(samples)

        classic_threshold = s.mean + 3 * s.stddev
        robust_threshold = s.median + 3.5 * s.mad * stats.MAD_TO_SIGMA

        assert classic_threshold > 1000, "the outlier inflated the classic threshold"
        assert robust_threshold < 50, "the robust threshold stays near the real data"
        # A genuine 500ms degradation: robust catches it, classic does not.
        assert classic_threshold > 500, "classic threshold would MISS a 500ms regression"
        assert robust_threshold < 500, "robust threshold catches it"

    def test_modified_z_score_flags_what_classic_z_misses(self) -> None:
        samples = [20, 21, 19, 22, 20, 2000]
        s = stats.summarise(samples)
        classic_z = (2000 - s.mean) / s.stddev
        robust_z = stats.modified_z_score(2000, s.median, s.mad)

        assert abs(classic_z) < 3.0, "classic z-score does not flag its own outlier"
        assert abs(robust_z) > 3.5, "modified z-score does"

    def test_modified_z_score_handles_zero_mad_without_dividing_by_zero(self) -> None:
        """Identical samples are common with coarse timers; inf would alert forever."""
        z = stats.modified_z_score(30.0, 20.0, 0.0)
        assert math.isfinite(z)
        assert z > 0
        assert stats.modified_z_score(0.0, 0.0, 0.0) == 0.0

    def test_tail_ratio_reflects_consistency(self) -> None:
        consistent = stats.summarise([20] * 50)
        spiky = stats.summarise([20] * 49 + [900])
        assert consistent.tail_ratio < 1.5
        assert spiky.tail_ratio > 5.0

    def test_jitter_rfc3550_is_zero_for_a_constant_series(self) -> None:
        assert stats.jitter_rfc3550([20.0] * 10) == pytest.approx(0.0)
        assert stats.jitter_rfc3550([20.0]) == 0.0

    def test_jitter_grows_with_variability(self) -> None:
        steady = stats.jitter_rfc3550([20, 20.5, 20, 20.5, 20])
        erratic = stats.jitter_rfc3550([20, 90, 15, 120, 25])
        assert erratic > steady * 5

    @pytest.mark.parametrize(
        "sent,received,expected", [(10, 10, 0.0), (10, 9, 10.0), (10, 0, 100.0), (0, 0, 0.0)]
    )
    def test_packet_loss(self, sent: int, received: int, expected: float) -> None:
        assert stats.packet_loss_pct(sent, received) == pytest.approx(expected)

    def test_mos_degrades_monotonically_with_conditions(self) -> None:
        """MOS must be ordered: a worse network cannot score better."""
        excellent = stats.mos_estimate(20, 2, 0)
        good = stats.mos_estimate(45, 8, 0.5)
        fair = stats.mos_estimate(120, 30, 2)
        bad = stats.mos_estimate(300, 60, 8)
        assert excellent > good > fair > bad

    def test_mos_stays_in_range(self) -> None:
        for rtt, jit, loss in [(0, 0, 0), (5000, 500, 100), (50, 10, 50)]:
            mos = stats.mos_estimate(rtt, jit, loss)
            assert 1.0 <= mos <= 5.0, f"MOS {mos} out of the 1-5 range"

    def test_loss_dominates_mos_more_than_latency(self) -> None:
        """A real property of the E-model, and the actionable insight it encodes."""
        high_latency = stats.mos_estimate(200, 5, 0)
        low_loss = stats.mos_estimate(30, 5, 5)
        assert low_loss < high_latency, "5% loss should hurt more than 200ms of latency"


# ---------------------------------------------------------------- endpoints


class TestEndpoints:
    def test_a_control_endpoint_exists(self) -> None:
        """Without a local control, Wi-Fi and ISP problems cannot be separated."""
        assert by_role(EndpointRole.CONTROL), "no control endpoint defined"

    def test_indian_isp_resolvers_are_present(self) -> None:
        names = {e.name for e in by_role(EndpointRole.ISP_DNS)}
        assert {"jio_dns", "airtel_dns"} <= names

    def test_an_international_reference_exists(self) -> None:
        """Needed so a high RTT to a far endpoint is not misread as a regression."""
        assert by_role(EndpointRole.INTERNATIONAL)

    def test_every_endpoint_is_fully_described(self) -> None:
        for e in ENDPOINTS:
            assert e.name and e.description, f"{e.name} is under-documented"
            assert e.expected_rtt_ms > 0

    def test_gateway_is_substituted_at_runtime(self) -> None:
        with_gw = resolve_gateway("192.168.1.1")
        gw = next(e for e in with_gw if e.name == "gateway")
        assert gw.host == "192.168.1.1"

    def test_gateway_is_dropped_when_not_discoverable(self) -> None:
        """Better to omit the control than to probe an empty host."""
        assert not [e for e in resolve_gateway(None) if e.name == "gateway"]


# ---------------------------------------------------------------- regression


@pytest.fixture
def kpi_db(tmp_path):
    conn = store.connect(tmp_path / "kpi.db")
    yield conn
    conn.close()


def _seed(conn, values, *, endpoint="ep", probe="icmp_rtt", network="net", band="5GHz"):
    rid = store.start_run(conn, dut_backend="macos")
    for v in values:
        store.record_kpi(conn, run_id=rid, network=network, band=band,
                         endpoint_name=endpoint, probe=probe, value=v,
                         unit="mbps" if probe == "throughput" else "ms")
    return rid


class TestBaselines:
    def test_baseline_needs_a_minimum_sample_count(self, kpi_db) -> None:
        _seed(kpi_db, [20] * (MIN_BASELINE_SAMPLES - 1))
        assert compute_baseline(kpi_db, network="net", band="5GHz",
                                endpoint="ep", probe="icmp_rtt") is None

    def test_baseline_is_built_once_there_are_enough_samples(self, kpi_db) -> None:
        _seed(kpi_db, [20, 21, 19, 22, 20, 21, 20, 19, 23, 20])
        b = compute_baseline(kpi_db, network="net", band="5GHz",
                             endpoint="ep", probe="icmp_rtt")
        assert b is not None
        assert b.median == pytest.approx(20.0, abs=1.0)
        assert b.mad < 2.0

    def test_baseline_ignores_an_outlier(self, kpi_db) -> None:
        _seed(kpi_db, [20, 21, 19, 22, 20, 21, 20, 19, 23, 20, 5000])
        b = compute_baseline(kpi_db, network="net", band="5GHz",
                             endpoint="ep", probe="icmp_rtt")
        assert b is not None
        assert b.median < 30, "one 5-second sample must not move the baseline"

    def test_relative_mad_identifies_a_noisy_metric(self) -> None:
        tight = Baseline("k", 20, 20.0, 1.0, 22, 23, 18, 24, "ms")
        noisy = Baseline("k", 20, 36.0, 18.0, 90, 95, 5, 100, "mbps")
        assert not tight.is_noisy
        assert noisy.is_noisy
        assert noisy.relative_mad == pytest.approx(0.5)

    def test_baselines_round_trip_through_the_store(self, kpi_db) -> None:
        b = Baseline(scope_key("net", "5GHz", "ep", "icmp_rtt"), 20, 20.0, 1.5,
                     24, 26, 18, 30, "ms")
        save_baseline(kpi_db, b)
        loaded = load_baseline(kpi_db, b.scope_key)
        assert loaded is not None
        assert loaded.median == pytest.approx(20.0)
        assert loaded.mad == pytest.approx(1.5)

    def test_baselines_are_scoped_per_band(self, kpi_db) -> None:
        """2.4GHz and 5GHz have genuinely different latency; merging them is wrong."""
        _seed(kpi_db, [20] * 10, band="5GHz")
        _seed(kpi_db, [60] * 10, band="2.4GHz")
        five = compute_baseline(kpi_db, network="net", band="5GHz",
                                endpoint="ep", probe="icmp_rtt")
        two = compute_baseline(kpi_db, network="net", band="2.4GHz",
                               endpoint="ep", probe="icmp_rtt")
        assert five and two
        assert five.median < two.median

    def test_rebuild_covers_every_scope(self, kpi_db) -> None:
        _seed(kpi_db, [20] * 10, endpoint="a", probe="icmp_rtt")
        _seed(kpi_db, [40] * 10, endpoint="b", probe="dns")
        built = rebuild_baselines(kpi_db)
        assert len(built) == 2


class TestRegressionDetection:
    @pytest.fixture
    def tight(self) -> Baseline:
        """A well-behaved metric: 20ms median, 1ms MAD."""
        return Baseline("net|5GHz|ep|icmp_rtt", 30, 20.0, 1.0, 23, 25, 18, 27, "ms")

    @pytest.fixture
    def noisy(self) -> Baseline:
        """A realistic throughput baseline, 51% relative MAD — as measured for real."""
        return Baseline("net|5GHz|ep|throughput", 30, 36.0, 18.0, 88, 95, 5, 100, "mbps")

    def test_value_at_baseline_is_ok(self, tight) -> None:
        assert check_value(20.0, "icmp_rtt", tight).verdict is Verdict.OK

    def test_small_change_is_within_tolerance(self, tight) -> None:
        """Small absolute moves on a fast link must not alert, despite a big z-score."""
        result = check_value(22.0, "icmp_rtt", tight)
        assert not result.is_regression

    def test_clear_latency_regression_is_flagged(self, tight) -> None:
        result = check_value(200.0, "icmp_rtt", tight)
        assert result.verdict is Verdict.CRITICAL
        assert result.is_regression

    def test_latency_improvement_is_not_a_regression(self, tight) -> None:
        """A two-sided test would report getting faster as a failure."""
        result = check_value(4.0, "icmp_rtt", tight)
        assert not result.is_regression
        assert result.verdict in (Verdict.IMPROVED, Verdict.OK)

    def test_throughput_collapse_is_caught_despite_a_noisy_baseline(self, noisy) -> None:
        """The bug from BUILD_JOURNAL #14, pinned permanently.

        A 9x throughput collapse scores only z=-1.2 against this baseline, so the
        z-test alone cannot see it. The ratio test must.
        """
        result = check_value(4.0, "throughput", noisy)
        assert result.verdict is Verdict.CRITICAL, (
            f"9x throughput collapse must be critical, got {result.verdict} "
            f"(z={result.z_score:.1f})"
        )
        assert abs(result.z_score) < 3.5, (
            "this test is only meaningful while the z-score alone would miss it"
        )

    def test_throughput_improvement_is_not_a_regression(self, noisy) -> None:
        result = check_value(180.0, "throughput", noisy)
        assert not result.is_regression
        assert result.verdict is Verdict.IMPROVED

    def test_ratio_thresholds_are_respected(self, noisy) -> None:
        just_under = check_value(36.0 / (SEVERE_RATIO * 0.9), "throughput", noisy)
        well_over = check_value(36.0 / (CRITICAL_RATIO * 1.2), "throughput", noisy)
        assert not just_under.is_regression
        assert well_over.verdict is Verdict.CRITICAL

    def test_noisy_baseline_is_labelled_in_the_message(self, noisy) -> None:
        result = check_value(12.0, "throughput", noisy)
        assert "noisy" in result.message.lower(), (
            "a verdict from a noisy baseline must say so"
        )

    def test_missing_baseline_is_not_a_pass(self) -> None:
        result = check_value(9999.0, "icmp_rtt", None)
        assert result.verdict is Verdict.NO_BASELINE
        assert not result.is_regression

    def test_thin_baseline_refuses_to_judge(self) -> None:
        thin = Baseline("k", 3, 20.0, 1.0, 22, 23, 19, 24, "ms")
        result = check_value(500.0, "icmp_rtt", thin)
        assert result.verdict is Verdict.INSUFFICIENT_DATA, (
            "a 3-sample baseline must not be used to declare a regression"
        )


# ---------------------------------------------------------------- live network


@pytest.mark.network
@pytest.mark.slow
class TestLiveProbes:
    """Real measurements. Deselect with -m 'not network'."""

    def test_public_dns_resolves_within_a_sane_time(self) -> None:
        from airframe.kpi.probes import probe_dns

        endpoint = by_name("cloudflare_dns")
        assert endpoint
        result = probe_dns(endpoint)
        if not result.ok:
            pytest.skip(f"DNS unreachable: {result.error}")
        assert result.value is not None
        assert 0 < result.value < 5000, f"implausible DNS time: {result.value}ms"

    def test_icmp_reports_rtt_loss_and_jitter(self) -> None:
        from airframe.kpi.probes import probe_icmp

        endpoint = by_name("cloudflare_dns")
        assert endpoint
        results = probe_icmp(endpoint, count=4)
        probes = {r.probe for r in results}
        assert "loss" in probes
        rtt = next((r for r in results if r.probe == "icmp_rtt"), None)
        if rtt is None or not rtt.ok:
            pytest.skip("ICMP appears to be filtered on this network")
        assert 0 < (rtt.value or 0) < 5000

    def test_http_ttfb_is_measurable(self) -> None:
        from airframe.kpi.probes import probe_http_ttfb

        endpoint = by_name("cloudflare_edge")
        assert endpoint
        result = probe_http_ttfb(endpoint)
        if not result.ok:
            pytest.skip(f"HTTP unreachable: {result.error}")
        assert 0 < (result.value or 0) < 30000

    def test_throughput_measurement_reports_its_method(self) -> None:
        """An HTTP-derived figure and an iperf3 figure are different measurements."""
        from airframe.kpi.probes import probe_throughput_http

        endpoint = by_name("cloudflare_edge")
        assert endpoint
        result = probe_throughput_http(endpoint, bytes_wanted=2_000_000)
        if not result.ok:
            pytest.skip(f"throughput probe failed: {result.error}")
        assert result.method, "the measurement method must be recorded"
        assert (result.value or 0) > 0

    def test_captive_portal_detection_runs(self) -> None:
        from airframe.kpi.probes import detect_captive_portal

        result = detect_captive_portal()
        if not result.ok:
            pytest.skip(f"captive portal check failed: {result.error}")
        assert result.extra.get("intercepted") in (True, False)

    def test_probes_never_raise_on_an_unreachable_host(self) -> None:
        """A failed measurement is data, not an exception."""
        from airframe.kpi.endpoints import Endpoint, EndpointRole
        from airframe.kpi.probes import probe_dns, probe_tcp_connect

        dead = Endpoint("dead", "192.0.2.1", EndpointRole.ISP_DNS,
                        "RFC 5737 reserved address, guaranteed unroutable",
                        supports_dns=True, port=53)
        for result in (probe_tcp_connect(dead, timeout_s=2.0),
                       probe_dns(dead, timeout_s=2.0)):
            assert not result.ok
            assert result.error, "a failure must explain itself"
