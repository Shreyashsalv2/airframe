"""Statistics for network measurements.

The central decision in this module: **robust statistics, not mean and standard
deviation.**

Network latency is heavy-tailed. A healthy connection producing 20ms samples all
day will occasionally produce a 2000ms sample — a retransmission, a DNS miss, a
Wi-Fi retry storm, a CPU stall on the measuring host. That single outlier is real
data, but it wrecks a mean and it wrecks a standard deviation far worse:

    samples : 20 21 19 22 20 2000   (ms)
    mean    : 350.3      <- describes nothing in the data
    stddev  : 807.6      <- so mean+3sigma is ~2773ms
    median  : 20.5       <- describes the data
    MAD     : 1.0

With mean+3σ as an alert threshold, that connection could degrade from 20ms to
2700ms without tripping anything. The outlier has *raised the threshold above the
failure it was meant to catch*. This is not a corner case; it is what happens
every time real latency data meets textbook statistics.

So the baseline is **median + MAD** (median absolute deviation), and the deviation
measure used for alerting is the **modified z-score**, which is the standard robust
analogue. Percentiles are also reported directly, because p95 and p99 are what
users actually experience and what SLAs are written against — the tail is the
product, and averaging it away hides the thing that matters.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

#: Converts MAD into a consistent estimator of the standard deviation for normally
#: distributed data (1 / Phi^-1(0.75) ~= 1.4826). Keeps the modified z-score on the
#: same scale as a conventional one, so a threshold of 3.5 means roughly what a
#: 3.5-sigma threshold would mean — just without the outlier sensitivity.
MAD_TO_SIGMA = 1.4826


def percentile(values: Sequence[float], p: float) -> float:
    """Linear-interpolation percentile (`p` in 0..100).

    Written out rather than pulled from numpy because the interpolation choice
    matters at small sample sizes, and because it should be obvious what is being
    computed when someone is reading a KPI report.
    """
    if not values:
        return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    k = (len(ordered) - 1) * (p / 100.0)
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return ordered[int(k)]
    return ordered[lo] * (hi - k) + ordered[hi] * (k - lo)


def median(values: Sequence[float]) -> float:
    return percentile(values, 50)


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation — the robust spread measure.

    Unlike a standard deviation, a single wild sample moves this almost not at all,
    which is exactly the property wanted for a network baseline.
    """
    if not values:
        return float("nan")
    m = median(values)
    return median([abs(v - m) for v in values])


def modified_z_score(value: float, med: float, mad_value: float) -> float:
    """Robust deviation score. |score| > 3.5 is the conventional outlier threshold.

    When MAD is exactly zero (every sample identical, which happens with
    low-resolution timers on a quiet link), fall back to a relative comparison
    rather than dividing by zero — a divide-by-zero here would report `inf` and
    alert on a perfectly stable connection.
    """
    if mad_value > 0:
        return 0.6745 * (value - med) / mad_value
    if med == 0:
        return 0.0
    return 10.0 * (value - med) / abs(med)


@dataclass(frozen=True)
class Summary:
    """Summary of one KPI series."""

    n: int
    median: float
    mad: float
    mean: float
    stddev: float
    p50: float
    p95: float
    p99: float
    minimum: float
    maximum: float
    unit: str = "ms"

    @property
    def jitter(self) -> float:
        """Spread as a robust interval — MAD scaled to sigma-equivalent units."""
        return self.mad * MAD_TO_SIGMA

    @property
    def tail_ratio(self) -> float:
        """p99 / p50. How much worse the worst experience is than the typical one.

        A ratio near 1 means a consistent connection; above ~5 means users regularly
        hit stalls even though the median looks healthy. This number is often more
        informative than either percentile alone.
        """
        return self.p99 / self.p50 if self.p50 else float("nan")

    def describe(self) -> str:
        return (
            f"n={self.n} median={self.median:.1f}{self.unit} "
            f"p95={self.p95:.1f} p99={self.p99:.1f} "
            f"mad={self.mad:.1f} tail={self.tail_ratio:.1f}x"
        )


def summarise(values: Sequence[float], unit: str = "ms") -> Summary:
    if not values:
        nan = float("nan")
        return Summary(0, nan, nan, nan, nan, nan, nan, nan, nan, nan, unit)
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n if n > 1 else 0.0
    return Summary(
        n=n,
        median=median(values),
        mad=mad(values),
        mean=mean,
        stddev=math.sqrt(variance),
        p50=percentile(values, 50),
        p95=percentile(values, 95),
        p99=percentile(values, 99),
        minimum=min(values),
        maximum=max(values),
        unit=unit,
    )


# ---------------------------------------------------------------- derived KPIs


def jitter_rfc3550(rtts: Sequence[float]) -> float:
    """Interarrival jitter, per RFC 3550 (the RTP specification).

    J = J + (|D(i-1,i)| - J) / 16, where D is the difference between consecutive
    transit times. This is a smoothed mean deviation, not a standard deviation, and
    it is the definition VoIP and video-conferencing systems actually use — so it is
    the number to quote when the question is "will calls be choppy".
    """
    if len(rtts) < 2:
        return 0.0
    j = 0.0
    for i in range(1, len(rtts)):
        d = abs(rtts[i] - rtts[i - 1])
        j += (d - j) / 16.0
    return j


def packet_loss_pct(sent: int, received: int) -> float:
    if sent <= 0:
        return 0.0
    return 100.0 * (sent - received) / sent


def mos_estimate(rtt_ms: float, jitter_ms: float, loss_pct: float) -> float:
    """Rough Mean Opinion Score (1..5) from the ITU-T G.107 E-model, simplified.

    Not a calibrated MOS — a real one needs codec parameters. It is included because
    it converts three abstract numbers into the one question a user cares about
    ("will my call be usable"), and because the *shape* of the relationship is the
    instructive part: loss dominates, and jitter hurts more than latency.
    """
    effective_latency = rtt_ms + jitter_ms * 2 + 10.0

    if effective_latency < 160:
        r = 93.2 - effective_latency / 40.0
    else:
        r = 93.2 - (effective_latency - 120) / 10.0

    # Loss is punishing: each 1% costs ~2.5 R-factor points.
    r -= loss_pct * 2.5
    r = max(0.0, min(100.0, r))

    if r < 0:
        return 1.0
    if r > 100:
        return 4.5
    mos = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    return max(1.0, min(5.0, mos))


def classify_mos(mos: float) -> str:
    if mos >= 4.3:
        return "excellent"
    if mos >= 4.0:
        return "good"
    if mos >= 3.6:
        return "fair"
    if mos >= 3.1:
        return "poor"
    return "unacceptable"
