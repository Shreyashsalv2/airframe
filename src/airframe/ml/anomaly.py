"""Unsupervised anomaly detection over KPI time series.

Complements `kpi/regression.py` rather than replacing it. The two answer different
questions and have different blind spots:

* **Threshold/baseline checks** (regression.py) are per-metric and explainable. They
  catch "DNS latency doubled" and tell you exactly which number moved. But they
  examine each metric in isolation.

* **IsolationForest** (here) looks at the *joint* distribution. It catches a
  combination of individually-normal values that never occurs together — latency
  normal, throughput normal, jitter normal, but this particular *combination* has
  never been seen. That is often what a real degradation looks like before any single
  metric crosses a threshold.

Why IsolationForest specifically: it isolates outliers by random splitting, so it
needs no assumption about distribution shape. That matters because network metrics
are heavy-tailed and multi-modal, which breaks anything Gaussian. It also trains in
seconds on thousands of samples and needs no labels.

The honest limitation, stated up front: anomaly detection tells you *that* a point is
unusual, not *why*. So every anomaly here is reported alongside the per-feature
deviations that made it unusual — an unexplained anomaly score is not actionable, and
an alert nobody can act on is an alert people learn to mute.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from airframe.kpi.stats import mad, median

#: Expected fraction of anomalies. Sets the decision threshold, and is genuinely a
#: judgement call: too low and real problems are missed, too high and the report is
#: noise. 5% is a reasonable default for a metric you check a few times a day.
DEFAULT_CONTAMINATION = 0.05

#: Below this, the model has nothing to learn from and the answer is "unknown".
MIN_TRAINING_SAMPLES = 20


@dataclass
class AnomalyPoint:
    index: int
    score: float                         # lower = more anomalous
    is_anomaly: bool
    values: dict[str, float] = field(default_factory=dict)
    deviations: dict[str, float] = field(default_factory=dict)

    def explain(self, top: int = 3) -> str:
        """Name the features that made this point unusual.

        This is what turns a score into something a human can act on.
        """
        if not self.deviations:
            return f"score={self.score:.3f}"
        ranked = sorted(self.deviations.items(), key=lambda kv: -abs(kv[1]))[:top]
        parts = [
            f"{name}={self.values.get(name, float('nan')):.1f} ({dev:+.1f} MAD)"
            for name, dev in ranked
        ]
        return f"score={self.score:.3f}  " + "  ".join(parts)


@dataclass
class AnomalyReport:
    features: list[str]
    points: list[AnomalyPoint]
    n_trained: int
    contamination: float
    trained: bool = True
    reason: str = ""

    @property
    def anomalies(self) -> list[AnomalyPoint]:
        return [p for p in self.points if p.is_anomaly]

    def report(self, limit: int = 12) -> str:
        if not self.trained:
            return f"anomaly detection skipped: {self.reason}"
        lines = [
            f"{len(self.anomalies)} anomalies in {len(self.points)} samples "
            f"({len(self.features)} features, contamination={self.contamination:.0%})",
            f"features: {', '.join(self.features)}",
            "",
        ]
        for point in sorted(self.anomalies, key=lambda p: p.score)[:limit]:
            lines.append(f"  sample {point.index:<5} {point.explain()}")
        return "\n".join(lines)


def detect(
    rows: list[dict[str, float]],
    *,
    contamination: float = DEFAULT_CONTAMINATION,
    random_state: int = 42,
) -> AnomalyReport:
    """Fit an IsolationForest over KPI rows and flag outliers.

    `random_state` is pinned so a rerun produces the same verdicts. An anomaly
    detector whose output changes between runs on identical data is impossible to
    build a workflow around.
    """
    if len(rows) < MIN_TRAINING_SAMPLES:
        return AnomalyReport(
            features=[], points=[], n_trained=len(rows), contamination=contamination,
            trained=False,
            reason=f"only {len(rows)} samples, need {MIN_TRAINING_SAMPLES}",
        )

    # Use only features present in every row, so missing probes cannot silently
    # become zeros — a zero is a meaningful latency value, and imputing it would
    # teach the model that a failed measurement is a very fast one.
    names = sorted(set.intersection(*(set(r) for r in rows)))
    if not names:
        return AnomalyReport(
            features=[], points=[], n_trained=len(rows), contamination=contamination,
            trained=False, reason="no feature is present across all samples",
        )

    matrix = np.array([[row[name] for name in names] for row in rows], dtype=float)

    # RobustScaler centres on the median and scales by the IQR, so a single extreme
    # sample does not compress everything else into a narrow band — the same
    # reasoning as median+MAD in kpi/stats.py, applied to preprocessing.
    scaled = RobustScaler().fit_transform(matrix)

    model = IsolationForest(
        contamination=contamination, random_state=random_state, n_estimators=200
    )
    labels = model.fit_predict(scaled)
    scores = model.score_samples(scaled)

    # Per-feature deviation in MAD units, so each anomaly can explain itself.
    medians = {name: median(matrix[:, i].tolist()) for i, name in enumerate(names)}
    mads = {name: mad(matrix[:, i].tolist()) or 1e-9 for i, name in enumerate(names)}

    points: list[AnomalyPoint] = []
    # strict=True: labels and scores both come from the same fitted model over the
    # same matrix, so unequal lengths would mean sklearn misbehaved.
    for i, (label, score) in enumerate(zip(labels, scores, strict=True)):
        values = {name: float(matrix[i, j]) for j, name in enumerate(names)}
        deviations = {
            name: (values[name] - medians[name]) / mads[name] for name in names
        }
        points.append(
            AnomalyPoint(index=i, score=float(score), is_anomaly=(label == -1),
                         values=values, deviations=deviations)
        )

    return AnomalyReport(features=names, points=points, n_trained=len(rows),
                         contamination=contamination)


def kpi_rows(
    conn: sqlite3.Connection, *, network: str | None = None, band: str | None = None
) -> list[dict[str, float]]:
    """Pivot stored KPI samples into one row per run.

    A row is a run's simultaneous measurements, which is the unit the joint
    distribution is defined over — feeding individual samples in would discard
    exactly the cross-metric relationship this model exists to find.
    """
    clauses = ["ok = 1", "value IS NOT NULL", "run_id IS NOT NULL"]
    args: list[object] = []
    if network:
        clauses.append("network = ?")
        args.append(network)
    if band:
        clauses.append("band = ?")
        args.append(band)

    rows = conn.execute(
        f"""SELECT run_id, endpoint_name, probe, value
            FROM kpi_samples WHERE {' AND '.join(clauses)}
            ORDER BY run_id""",
        args,
    ).fetchall()

    by_run: dict[int, dict[str, float]] = {}
    for row in rows:
        key = f"{row['endpoint_name']}.{row['probe']}"
        by_run.setdefault(int(row["run_id"]), {})[key] = float(row["value"])
    return list(by_run.values())


def _main() -> int:
    import argparse

    from airframe.store import db as store

    ap = argparse.ArgumentParser(description="detect KPI anomalies")
    ap.add_argument("--contamination", type=float, default=DEFAULT_CONTAMINATION)
    ap.add_argument("--network")
    args = ap.parse_args()

    conn = store.connect()
    try:
        rows = kpi_rows(conn, network=args.network)
        print(f"loaded {len(rows)} KPI runs")
        print(detect(rows, contamination=args.contamination).report())
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
