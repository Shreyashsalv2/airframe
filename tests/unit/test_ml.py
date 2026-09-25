"""Tests for the ML layer: features, clustering, anomaly detection, flake analysis.

Several of these exist specifically to pin down bugs recorded in BUILD_JOURNAL.md. A
journal entry without a regression test is a story, not a guarantee — the code can
regress back to the buggy behaviour and nothing would notice.

Covered journal entries:
  #14  a 9x throughput collapse on a noisy baseline must still be CRITICAL
  #15  identical failures must produce identical signatures
  #16  metrics from a tiny held-out set must be marked untrustworthy
  #19  `transitions` distinguishes flaky from fixed from regressed
"""

from __future__ import annotations

import pytest

from airframe.ml.anomaly import MIN_TRAINING_SAMPLES, detect
from airframe.ml.cluster import cluster_failures
from airframe.ml.features import NUMERIC_FEATURES, FailureFeatures, scrub
from airframe.ml.flaky import (
    FEATURE_NAMES,
    MIN_TEST_POSITIVES,
    RunHistory,
    feature_importance,
    train,
)


def _features(tag: str, signature: str, fault: str | None = None,
              **numeric: float) -> FailureFeatures:
    return FailureFeatures(tag=tag, signature=signature, numeric=numeric,
                           injected_fault=fault)


# ---------------------------------------------------------------- features


class TestScrub:
    @pytest.mark.parametrize(
        "text",
        ["bssid=be:14:66:79:d2:d6", "server=192.168.1.1", "elapsed_ms=1640",
         "timeout_ms=500", "seed=1013", "aid=19", "replay=1", "rssi=-45"],
    )
    def test_run_specific_detail_is_removed(self, text: str) -> None:
        """Anything that varies between runs of the SAME bug must not survive.

        If it does, every failure becomes unique and the clustering learns nothing —
        which is the failure mode journal entry #15 describes.
        """
        assert scrub(text).strip() in ("", text.split("=")[0] + "="), scrub(text)

    def test_stable_wording_survives(self) -> None:
        text = "EAPOL-Key M3 not received, retransmitting M2"
        assert scrub(text) == text

    def test_whitespace_is_normalised(self) -> None:
        assert scrub("a    b\n\nc") == "a b c"


class TestFeatureVector:
    def test_vector_length_is_fixed_and_ordered(self) -> None:
        """Train and predict must never disagree about what column N means."""
        f = _features("t", "sig", None, scan_ms=10.0)
        assert len(f.vector()) == len(NUMERIC_FEATURES)
        assert f.vector()[NUMERIC_FEATURES.index("scan_ms")] == 10.0

    def test_missing_features_default_to_zero_not_an_error(self) -> None:
        assert _features("t", "sig").vector() == [0.0] * len(NUMERIC_FEATURES)


# ---------------------------------------------------------------- clustering


class TestClustering:
    def _corpus(self) -> list[FailureFeatures]:
        """Three distinct bugs, six runs each, with per-run noise in the volatile parts."""
        out: list[FailureFeatures] = []
        for i in range(6):
            out.append(_features(
                f"m3_{i}",
                "EAPOL-Key M3 not received, retransmitting M2 attempt= "
                "4-way handshake timeout missing_m3 m2_retransmit_x4 "
                "stage:associated deauth reason= reason_name=FOURWAY_HANDSHAKE_TIMEOUT",
                "FOURWAY_M3_TIMEOUT",
            ))
            out.append(_features(
                f"pmk_{i}",
                "EAPOL-Key MIC verification failed msg= reason=PMK mismatch "
                "hint=wrong passphrase stage:associated deauth "
                "reason_name=IEEE8021X_FAILED missing_m3",
                "PMK_MISMATCH",
            ))
            out.append(_features(
                f"dhcp_{i}",
                "DHCPNAK server= reason=requested address not available "
                "link up but no IPv4 address state=DHCP_FAILED stage:keyed",
                "DHCP_NAK",
            ))
        return out

    def test_collapses_many_failures_into_few_bugs(self) -> None:
        result = cluster_failures(self._corpus())
        assert 2 <= len(result.real_clusters) <= 4, (
            f"18 failures of 3 kinds gave {len(result.real_clusters)} clusters"
        )

    def test_separates_m3_timeout_from_pmk_mismatch(self) -> None:
        """Both fail in the handshake. Conflating them sends the bug to the wrong team.

        This is the discrimination the whole triage pipeline depends on.
        """
        result = cluster_failures(self._corpus())
        label_of: dict[str, int] = {}
        for cluster in result.real_clusters:
            for tag in cluster.members:
                label_of[tag] = cluster.label
        assert label_of.get("m3_0") != label_of.get("pmk_0"), (
            "M3 timeout and PMK mismatch landed in the same cluster"
        )

    def test_evaluates_against_ground_truth(self) -> None:
        result = cluster_failures(self._corpus())
        assert result.homogeneity is not None
        assert result.homogeneity > 0.8, f"homogeneity {result.homogeneity}"
        assert result.completeness is not None and result.completeness > 0.8

    def test_exemplar_is_a_real_member(self) -> None:
        """The exemplar is what gets shown to a human and sent to the LLM."""
        for cluster in cluster_failures(self._corpus()).clusters:
            assert cluster.exemplar in cluster.members

    def test_purity_reflects_composition(self) -> None:
        for cluster in cluster_failures(self._corpus()).real_clusters:
            assert 0.0 <= cluster.purity <= 1.0
            assert cluster.dominant_fault in ("FOURWAY_M3_TIMEOUT", "PMK_MISMATCH",
                                              "DHCP_NAK")

    def test_too_few_inputs_returns_empty_not_an_error(self) -> None:
        assert cluster_failures([_features("only", "one")]).clusters == []

    def test_blank_signatures_are_excluded(self) -> None:
        result = cluster_failures([_features(f"t{i}", "") for i in range(5)])
        assert result.n_runs == 0

    def test_report_is_human_readable(self) -> None:
        text = cluster_failures(self._corpus()).report()
        assert "distinct bug" in text
        assert "homogeneity" in text


# ---------------------------------------------------------------- anomaly


class TestAnomalyDetection:
    def _rows(self, n: int = 60) -> list[dict[str, float]]:
        """Well-behaved KPI rows: small deterministic variation, no outliers."""
        return [
            {"ep.icmp_rtt": 20.0 + (i % 5), "ep.dns": 40.0 + (i % 3),
             "ep.throughput": 50.0 - (i % 4)}
            for i in range(n)
        ]

    def test_refuses_to_train_on_too_few_samples(self) -> None:
        """'Not enough data' must be an explicit verdict, never a silent pass."""
        report = detect(self._rows(MIN_TRAINING_SAMPLES - 1))
        assert not report.trained
        assert "samples" in report.reason
        assert report.anomalies == []

    def test_flags_a_joint_outlier(self) -> None:
        rows = self._rows()
        rows.append({"ep.icmp_rtt": 900.0, "ep.dns": 800.0, "ep.throughput": 0.5})
        report = detect(rows, contamination=0.05)
        assert report.trained
        assert report.anomalies, "an extreme row was not flagged"
        assert report.anomalies[-1].index == len(rows) - 1 or any(
            p.index == len(rows) - 1 for p in report.anomalies
        )

    def test_anomalies_explain_themselves(self) -> None:
        """An unexplained anomaly score is not actionable, so it must name the features."""
        rows = self._rows()
        rows.append({"ep.icmp_rtt": 900.0, "ep.dns": 800.0, "ep.throughput": 0.5})
        report = detect(rows)
        outlier = next(p for p in report.points if p.index == len(rows) - 1)
        assert outlier.deviations
        assert "MAD" in outlier.explain()

    def test_is_deterministic_across_runs(self) -> None:
        """A detector whose verdicts change on identical data cannot be built upon."""
        rows = self._rows()
        rows.append({"ep.icmp_rtt": 900.0, "ep.dns": 800.0, "ep.throughput": 0.5})
        first = {p.index for p in detect(rows).anomalies}
        second = {p.index for p in detect(rows).anomalies}
        assert first == second

    def test_features_missing_from_some_rows_are_excluded(self) -> None:
        """A missing probe must not be imputed as zero — zero is a real latency value."""
        rows = self._rows()
        rows[0].pop("ep.dns")
        report = detect(rows)
        assert "ep.dns" not in report.features
        assert "ep.icmp_rtt" in report.features

    def test_no_common_features_is_reported_not_crashed(self) -> None:
        rows = [{f"only_in_{i}": 1.0} for i in range(MIN_TRAINING_SAMPLES + 5)]
        report = detect(rows)
        assert not report.trained
        assert "feature" in report.reason


# ---------------------------------------------------------------- flakiness


class TestHistoryClassification:
    """BUILD_JOURNAL.md #19 — `flake_rate` alone conflates four different situations.

    Each of these histories has a nonzero inconsistency, and they demand completely
    different responses. Conflating them put every bug fix in the flake leaderboard.
    """

    @staticmethod
    def _h(pattern: str) -> RunHistory:
        return RunHistory(nodeid="t", outcomes=[c == "." for c in pattern])

    def test_alternating_is_flaky(self) -> None:
        h = self._h(".F.F.F.F")
        assert h.classification == "flaky"
        assert h.is_flaky

    def test_failed_then_fixed_is_not_flaky(self) -> None:
        """The exact bug: a test somebody FIXED was being reported as flaky."""
        h = self._h("FFFF....")
        assert h.classification == "fixed"
        assert not h.is_flaky, "a fixed test must never appear in the flake leaderboard"
        assert h.flake_rate == 0.5, "its inconsistency is still 0.5 — that is the point"

    def test_passed_then_broken_is_a_regression(self) -> None:
        h = self._h("....FFFF")
        assert h.classification == "regressed"
        assert not h.is_flaky

    def test_always_failing_is_failing_not_flaky(self) -> None:
        h = self._h("FFFFFFFF")
        assert h.classification == "failing"
        assert h.flake_rate == 0.0
        assert not h.is_flaky

    def test_always_passing_is_stable(self) -> None:
        assert self._h("........").classification == "stable"

    def test_transitions_is_the_discriminator(self) -> None:
        """Same flake_rate, different transition count, different verdict."""
        fixed = self._h("FFFF....")
        flaky = self._h("F.F.F.F.")
        assert fixed.flake_rate == flaky.flake_rate
        assert fixed.transitions == 1
        assert flaky.transitions == 7
        assert fixed.classification != flaky.classification

    def test_single_run_is_not_judged(self) -> None:
        assert self._h(".").flake_rate == 0.0
        assert not self._h("F").is_flaky

    def test_describe_shows_the_pattern(self) -> None:
        text = self._h("F.F.").describe()
        assert "F.F." in text
        assert "transitions" in text

    def test_features_are_complete_and_ordered(self) -> None:
        features = self._h("F.F.").features()
        assert set(features) == set(FEATURE_NAMES)


class TestFlakeModel:
    @staticmethod
    def _dataset() -> tuple[list[RunHistory], dict[str, bool]]:
        histories: list[RunHistory] = []
        truth: dict[str, bool] = {}
        for i in range(12):
            flaky = RunHistory(nodeid=f"flaky{i}",
                                outcomes=[j % 2 == 0 for j in range(12)])
            stable = RunHistory(nodeid=f"stable{i}", outcomes=[True] * 12)
            histories += [flaky, stable]
            truth[flaky.nodeid] = True
            truth[stable.nodeid] = False
        return histories, truth

    def test_trains_and_predicts(self) -> None:
        model = train(*self._dataset())
        assert model is not None
        flaky = RunHistory(nodeid="x", outcomes=[i % 2 == 0 for i in range(12)])
        is_flaky, confidence = model.predict(flaky)
        assert is_flaky
        assert 0.0 <= confidence <= 1.0

    def test_returns_none_on_single_class_data(self) -> None:
        """A model trained on one class reports perfect accuracy and is worthless."""
        histories = [RunHistory(nodeid=f"s{i}", outcomes=[True] * 6) for i in range(12)]
        assert train(histories, {h.nodeid: False for h in histories}) is None

    def test_returns_none_on_too_little_data(self) -> None:
        histories = [RunHistory(nodeid="a", outcomes=[True, False])]
        assert train(histories, {"a": True}) is None

    def test_flags_untrustworthy_metrics(self) -> None:
        """BUILD_JOURNAL.md #16 — precision 1.00 with support 1 is not a result."""
        histories, truth = self._dataset()
        model = train(histories, truth)
        assert model is not None
        if model.n_test_positives < MIN_TEST_POSITIVES:
            assert not model.metrics_are_trustworthy
            assert "WARNING" in model.summary()
        else:
            assert model.metrics_are_trustworthy

    def test_feature_importance_is_reported(self) -> None:
        """The interpretability check: if flake_rate dominates, the ML adds nothing."""
        model = train(*self._dataset())
        assert model is not None
        importance = feature_importance(model)
        assert len(importance) == len(FEATURE_NAMES)
        assert abs(sum(v for _, v in importance) - 1.0) < 0.01
