"""Baseline management and regression detection.

The question this answers: *"is the network worse than it used to be?"* — which is
much harder than "is the network slow", because slow-in-absolute-terms depends
entirely on the connection. 80ms is excellent on rural 4G and terrible on urban
fibre, so any fixed threshold is wrong for someone.

The approach:

1. **Learn a baseline per scope.** A scope is `network|band|endpoint|probe` — for
   example `MyWiFi|5GHz|cloudflare_dns|dns`. Baselining per scope rather than
   globally is essential: the same laptop on the same network has genuinely
   different latency on 2.4 GHz versus 5 GHz, and mixing them produces a baseline
   that fits neither.

2. **Store median + MAD, not mean + stddev** (see `stats.py` for the full argument,
   with a worked example of mean+3σ setting a threshold *above* the failure it was
   supposed to catch).

3. **Flag using a modified z-score**, with direction awareness: for latency, higher
   is worse; for throughput, lower is worse. A naive two-sided test would report
   "regression" when your connection got faster, which is the sort of alert that
   teaches people to ignore alerts.

4. **Refuse to judge without enough data.** Under `MIN_BASELINE_SAMPLES` the verdict
   is `INSUFFICIENT_DATA`, not "pass". A regression detector that is confident after
   three samples is a random number generator with good manners.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import Enum

from airframe.kpi.stats import MAD_TO_SIGMA, mad, median, modified_z_score, percentile
from airframe.store import db as store

#: Below this many samples, no verdict is issued. Chosen because MAD needs a
#: reasonable spread of values to mean anything; with 5 samples a single outlier is
#: 20% of the data.
MIN_BASELINE_SAMPLES = 8

#: Modified-z threshold. 3.5 is the conventional cutoff for outlier detection with
#: MAD-based scores (Iglewicz & Hoaglin), and keeps the scale comparable to a
#: 3.5-sigma test without inheriting sigma's outlier sensitivity.
Z_WARN = 3.5
Z_CRITICAL = 7.0

#: Some probes are "lower is better" (latency), others "higher is better"
#: (throughput). Getting this backwards means reporting improvements as failures.
HIGHER_IS_WORSE = {"icmp_rtt", "dns", "tcp_connect", "tls_handshake", "http_ttfb",
                   "jitter", "loss"}
HIGHER_IS_BETTER = {"throughput"}

#: A relative floor, so tiny absolute changes on very fast links do not trip an
#: alert. Going from 2ms to 4ms is a 100% increase and a huge z-score, but nobody
#: perceives it — without this, a stable fast connection alerts constantly.
MIN_RELATIVE_CHANGE = 0.25

#: A ratio test that runs ALONGSIDE the z-score, and the reason it has to exist.
#:
#: A z-score can only detect a change larger than the metric's natural variance.
#: Real throughput measurements over a home connection have a MAD/median ratio
#: around 0.5 — i.e. 50% natural variability — so a genuine 36 Mbps -> 4 Mbps
#: collapse scores only z=-1.2 and passes a 3.5 threshold cleanly. That is not a
#: tuning problem: with that much variance, no z-threshold can separate an 89% drop
#: from noise without also firing on noise.
#:
#: The fix is a second, scale-free test. A value this many times worse than the
#: baseline median is a regression regardless of what the z-score says, because a
#: 2.5x change is qualitatively different behaviour rather than a bad sample.
SEVERE_RATIO = 2.5
CRITICAL_RATIO = 4.0

#: Above this MAD/median ratio a baseline is too noisy for z-scoring to mean much,
#: and the verdict says so rather than implying a precision it does not have.
NOISY_BASELINE_RATIO = 0.35


class Verdict(str, Enum):
    OK = "ok"
    IMPROVED = "improved"
    WARNING = "warning"
    CRITICAL = "critical"
    INSUFFICIENT_DATA = "insufficient_data"
    NO_BASELINE = "no_baseline"


@dataclass
class Baseline:
    scope_key: str
    n: int
    median: float
    mad: float
    p95: float
    p99: float
    minimum: float
    maximum: float
    unit: str

    @property
    def upper_bound(self) -> float:
        """Where a latency value starts being suspicious."""
        return self.median + Z_WARN * self.mad * MAD_TO_SIGMA

    @property
    def lower_bound(self) -> float:
        return self.median - Z_WARN * self.mad * MAD_TO_SIGMA

    @property
    def relative_mad(self) -> float:
        """MAD / median — how noisy this metric naturally is.

        The single most useful number for judging whether a baseline is worth
        anything. Near 0 means a tight, predictable metric where small deviations
        are meaningful; above ~0.35 means the metric swings so much by itself that
        only large, ratio-scale changes can be distinguished from noise.
        """
        return self.mad / self.median if self.median else 0.0

    @property
    def is_noisy(self) -> bool:
        return self.relative_mad > NOISY_BASELINE_RATIO


@dataclass
class RegressionResult:
    scope_key: str
    probe: str
    value: float
    verdict: Verdict
    z_score: float = 0.0
    baseline: Baseline | None = None
    message: str = ""

    @property
    def is_regression(self) -> bool:
        return self.verdict in (Verdict.WARNING, Verdict.CRITICAL)

    def __str__(self) -> str:
        tag = {
            Verdict.OK: "OK  ",
            Verdict.IMPROVED: "BETR",
            Verdict.WARNING: "WARN",
            Verdict.CRITICAL: "CRIT",
            Verdict.INSUFFICIENT_DATA: "----",
            Verdict.NO_BASELINE: "NEW ",
        }[self.verdict]
        return f"[{tag}] {self.scope_key:<48} {self.message}"


def scope_key(network: str, band: str, endpoint: str, probe: str) -> str:
    """Build the baseline scope identifier. Order is fixed so keys sort usefully."""
    return f"{network}|{band}|{endpoint}|{probe}"


def parse_scope(key: str) -> tuple[str, str, str, str]:
    parts = key.split("|")
    while len(parts) < 4:
        parts.append("")
    return tuple(parts[:4])  # type: ignore[return-value]


# ---------------------------------------------------------------- baselines


def compute_baseline(
    conn: sqlite3.Connection,
    *,
    network: str,
    band: str,
    endpoint: str,
    probe: str,
    window: int = 200,
) -> Baseline | None:
    """Derive a baseline from stored samples. None when there are too few."""
    values = store.kpi_values(
        conn, network=network, band=band, endpoint_name=endpoint, probe=probe, limit=window
    )
    if len(values) < MIN_BASELINE_SAMPLES:
        return None

    key = scope_key(network, band, endpoint, probe)
    unit = "mbps" if probe == "throughput" else ("pct" if probe == "loss" else "ms")
    return Baseline(
        scope_key=key,
        n=len(values),
        median=median(values),
        mad=mad(values),
        p95=percentile(values, 95),
        p99=percentile(values, 99),
        minimum=min(values),
        maximum=max(values),
        unit=unit,
    )


def save_baseline(conn: sqlite3.Connection, baseline: Baseline) -> None:
    store.upsert_baseline(
        conn,
        scope_key=baseline.scope_key,
        n=baseline.n,
        median=baseline.median,
        mad=baseline.mad,
        p95=baseline.p95,
        p99=baseline.p99,
        min_value=baseline.minimum,
        max_value=baseline.maximum,
        unit=baseline.unit,
    )


def load_baseline(conn: sqlite3.Connection, key: str) -> Baseline | None:
    row = store.get_baseline(conn, key)
    if row is None:
        return None
    return Baseline(
        scope_key=row["scope_key"],
        n=int(row["n"]),
        median=float(row["median"]),
        mad=float(row["mad"]),
        p95=float(row["p95"] or 0.0),
        p99=float(row["p99"] or 0.0),
        minimum=float(row["min_value"] or 0.0),
        maximum=float(row["max_value"] or 0.0),
        unit=str(row["unit"] or "ms"),
    )


def rebuild_baselines(conn: sqlite3.Connection, window: int = 200) -> list[Baseline]:
    """Recompute every baseline from the samples currently stored."""
    scopes = conn.execute(
        """SELECT DISTINCT network, band, endpoint_name, probe
           FROM kpi_samples WHERE ok = 1 AND value IS NOT NULL"""
    ).fetchall()

    built: list[Baseline] = []
    for row in scopes:
        baseline = compute_baseline(
            conn,
            network=row["network"] or "",
            band=row["band"] or "",
            endpoint=row["endpoint_name"],
            probe=row["probe"],
            window=window,
        )
        if baseline:
            save_baseline(conn, baseline)
            built.append(baseline)
    return built


# ---------------------------------------------------------------- detection


def check_value(
    value: float, probe: str, baseline: Baseline | None, *, key: str = ""
) -> RegressionResult:
    """Compare one measurement against its baseline."""
    key = key or (baseline.scope_key if baseline else "")

    if baseline is None:
        return RegressionResult(key, probe, value, Verdict.NO_BASELINE,
                                message=f"{value:.2f} (no baseline yet)")
    if baseline.n < MIN_BASELINE_SAMPLES:
        return RegressionResult(
            key, probe, value, Verdict.INSUFFICIENT_DATA, baseline=baseline,
            message=f"{value:.2f} (only {baseline.n} baseline samples, need "
                    f"{MIN_BASELINE_SAMPLES})",
        )

    z = modified_z_score(value, baseline.median, baseline.mad)
    relative = abs(value - baseline.median) / baseline.median if baseline.median else 0.0

    worse_when_higher = probe in HIGHER_IS_WORSE
    worse_when_lower = probe in HIGHER_IS_BETTER
    got_worse = (z > 0 and worse_when_higher) or (z < 0 and worse_when_lower)

    detail = (
        f"{value:.2f}{baseline.unit} vs baseline {baseline.median:.2f}"
        f"±{baseline.mad:.2f} (z={z:+.1f}, {relative:+.0%})"
    )

    # Tiny absolute movements on a fast link produce huge z-scores. Requiring a
    # meaningful relative change as well is what stops a perfectly stable 2ms link
    # from alerting every time it reads 3ms.
    if relative < MIN_RELATIVE_CHANGE:
        return RegressionResult(key, probe, value, Verdict.OK, z, baseline,
                                f"{detail} — within tolerance")

    # ---- ratio test, run alongside the z-score ----
    #
    # Computed so that `ratio` is always ">= 1 means worse", whichever direction
    # this probe degrades in. This is what catches large changes on noisy metrics
    # that the z-score structurally cannot see (see SEVERE_RATIO).
    ratio = 1.0
    if baseline.median > 0:
        if worse_when_higher:
            ratio = value / baseline.median
        elif worse_when_lower and value > 0:
            ratio = baseline.median / value
        elif worse_when_lower:
            ratio = float("inf")        # throughput fell to zero
    noise_note = " [noisy baseline]" if baseline.is_noisy else ""

    if not got_worse and (abs(z) > Z_WARN or ratio_improved(value, baseline, probe)):
        return RegressionResult(key, probe, value, Verdict.IMPROVED, z, baseline,
                                f"{detail} — improved")

    if got_worse and (abs(z) >= Z_CRITICAL or ratio >= CRITICAL_RATIO):
        why = "z-score" if abs(z) >= Z_CRITICAL else f"{ratio:.1f}x worse than baseline"
        return RegressionResult(key, probe, value, Verdict.CRITICAL, z, baseline,
                                f"{detail} — CRITICAL regression ({why}){noise_note}")

    if got_worse and (abs(z) >= Z_WARN or ratio >= SEVERE_RATIO):
        why = "z-score" if abs(z) >= Z_WARN else f"{ratio:.1f}x worse than baseline"
        return RegressionResult(key, probe, value, Verdict.WARNING, z, baseline,
                                f"{detail} — regression ({why}){noise_note}")

    return RegressionResult(key, probe, value, Verdict.OK, z, baseline, detail + noise_note)


def ratio_improved(value: float, baseline: Baseline, probe: str) -> bool:
    """Symmetric counterpart to the ratio regression test, for improvements."""
    if baseline.median <= 0:
        return False
    if probe in HIGHER_IS_BETTER:
        return value / baseline.median >= SEVERE_RATIO
    if probe in HIGHER_IS_WORSE and value > 0:
        return baseline.median / value >= SEVERE_RATIO
    return False


def check_samples(
    conn: sqlite3.Connection, samples: list[tuple[str, str, str, str, float]]
) -> list[RegressionResult]:
    """Check a batch of (network, band, endpoint, probe, value) tuples."""
    out: list[RegressionResult] = []
    for network, band, endpoint, probe, value in samples:
        key = scope_key(network, band, endpoint, probe)
        out.append(check_value(value, probe, load_baseline(conn, key), key=key))
    return out


def detect_regressions(conn: sqlite3.Connection, run_id: int) -> list[RegressionResult]:
    """Check every KPI sample recorded in a run against the stored baselines."""
    rows = conn.execute(
        """SELECT network, band, endpoint_name, probe, value
           FROM kpi_samples
           WHERE run_id = ? AND ok = 1 AND value IS NOT NULL""",
        (run_id,),
    ).fetchall()
    return check_samples(
        conn,
        [
            (r["network"] or "", r["band"] or "", r["endpoint_name"], r["probe"],
             float(r["value"]))
            for r in rows
        ],
    )
