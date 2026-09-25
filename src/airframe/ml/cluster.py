"""Failure clustering — collapsing many red tests into a few distinct bugs.

The highest-leverage thing a quality-engineering automation layer can deliver. A
matrix run produces 200 failures; an engineer can act on "four distinct bugs, here
is one example of each". Without this, triage is reading 200 tracebacks and
recognising duplicates by hand, which is where QE time actually goes.

Method: TF-IDF over the text signature, then DBSCAN on cosine distance.

* **TF-IDF** weights tokens by how *discriminative* they are. Tokens appearing in
  every failure ("state", "transition", "wifid") get near-zero weight automatically;
  "missing_m3" and "reason" get high weight. This is why no manual stop-word list is
  needed — the maths does it.

* **DBSCAN** rather than k-means, for one decisive reason: **it does not require the
  number of clusters up front.** You never know in advance how many distinct bugs a
  run contains — that is the question being asked. DBSCAN also has an explicit noise
  label (-1) for genuinely one-off failures, whereas k-means must force every point
  into some cluster, so a unique failure corrupts whichever centroid it lands near.

Evaluation is honest because the simulator injected known faults: clusters can be
scored against ground truth with homogeneity and completeness rather than eyeballed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
)

from airframe.ml.features import FailureFeatures

#: Cosine-distance radius. 0.35 is loose enough to join the same bug across
#: scenarios (a 2.4GHz M3 timeout and a 5GHz one) and tight enough not to merge an
#: auth timeout with a DHCP failure. Tuned against the labelled corpus, which is the
#: only defensible way to pick it.
DEFAULT_EPS = 0.35

#: Two runs is enough to call something a cluster: the whole point is spotting
#: repeated failures, and requiring more would hide a bug that has struck twice.
DEFAULT_MIN_SAMPLES = 2


@dataclass
class Cluster:
    label: int
    members: list[str] = field(default_factory=list)          # tags
    exemplar: str = ""                                        # most central member
    signature: str = ""
    injected_faults: Counter[str] = field(default_factory=Counter)

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def is_noise(self) -> bool:
        return self.label == -1

    @property
    def purity(self) -> float:
        """Fraction of members sharing the most common injected fault.

        1.0 means the cluster is exactly one bug. Only computable because ground
        truth exists; in production this is what a human reviewer replaces.
        """
        if not self.injected_faults:
            return 0.0
        return self.injected_faults.most_common(1)[0][1] / sum(self.injected_faults.values())

    @property
    def dominant_fault(self) -> str:
        return self.injected_faults.most_common(1)[0][0] if self.injected_faults else "unknown"

    def describe(self) -> str:
        if self.is_noise:
            return f"noise ({self.size} unique failures): {', '.join(self.members[:4])}"
        return (
            f"cluster {self.label} ({self.size} runs, purity {self.purity:.0%}, "
            f"dominant={self.dominant_fault})\n"
            f"    exemplar : {self.exemplar}\n"
            f"    signature: {self.signature[:150]}"
        )


@dataclass
class ClusteringResult:
    clusters: list[Cluster]
    n_runs: int
    homogeneity: float | None = None
    completeness: float | None = None
    adjusted_rand: float | None = None

    @property
    def real_clusters(self) -> list[Cluster]:
        return [c for c in self.clusters if not c.is_noise]

    @property
    def noise_count(self) -> int:
        return sum(c.size for c in self.clusters if c.is_noise)

    def report(self) -> str:
        lines = [
            f"{self.n_runs} failures collapsed into {len(self.real_clusters)} distinct "
            f"bug(s) plus {self.noise_count} one-off(s)",
        ]
        if self.homogeneity is not None:
            lines.append(
                f"vs ground truth: homogeneity={self.homogeneity:.2f} "
                f"completeness={self.completeness:.2f} ARI={self.adjusted_rand:.2f}"
            )
            lines.append(
                "  (homogeneity: each cluster contains one bug. "
                "completeness: each bug lands in one cluster.)"
            )
        lines.append("")
        for cluster in sorted(self.clusters, key=lambda c: (c.is_noise, -c.size)):
            lines.append("  " + cluster.describe().replace("\n", "\n  "))
        return "\n".join(lines)


def cluster_failures(
    features: list[FailureFeatures],
    *,
    eps: float = DEFAULT_EPS,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> ClusteringResult:
    """Group failures by signature similarity."""
    usable = [f for f in features if f.signature.strip()]
    if len(usable) < 2:
        return ClusteringResult(clusters=[], n_runs=len(usable))

    vectorizer = TfidfVectorizer(
        # Character n-grams rather than words: log signatures contain tokens like
        # "missing_m3" and "reason=15" that word tokenisation splits badly, and
        # char n-grams are robust to that without needing a custom tokeniser.
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=1,
        sublinear_tf=True,
    )
    matrix = vectorizer.fit_transform([f.signature for f in usable])

    model = DBSCAN(eps=eps, min_samples=min_samples, metric="cosine")
    labels = model.fit_predict(matrix)

    dense = matrix.toarray()
    clusters: dict[int, Cluster] = {}
    # strict=True: one label per input row is an invariant of fit_predict.
    for feature, label in zip(usable, labels, strict=True):
        cluster = clusters.setdefault(int(label), Cluster(label=int(label)))
        cluster.members.append(feature.tag)
        if feature.injected_fault:
            cluster.injected_faults[feature.injected_fault] += 1

    # Exemplar = the member closest to the cluster centroid, i.e. the most
    # representative example. This is what gets shown to a human and what gets sent
    # to the LLM for triage, so picking a central member rather than an arbitrary one
    # matters.
    for label, cluster in clusters.items():
        if label == -1:
            cluster.exemplar = cluster.members[0]
            cluster.signature = next(
                f.signature for f in usable if f.tag == cluster.members[0]
            )
            continue
        idx = [i for i, lbl in enumerate(labels) if lbl == label]
        centroid = dense[idx].mean(axis=0)
        distances = [float(np.linalg.norm(dense[i] - centroid)) for i in idx]
        best = idx[int(np.argmin(distances))]
        cluster.exemplar = usable[best].tag
        cluster.signature = usable[best].signature

    result = ClusteringResult(clusters=list(clusters.values()), n_runs=len(usable))

    # ---- evaluation against ground truth ----
    truth = [f.injected_fault for f in usable]
    if all(t is not None for t in truth) and len(set(truth)) > 1:
        result.homogeneity = float(homogeneity_score(truth, labels))
        result.completeness = float(completeness_score(truth, labels))
        result.adjusted_rand = float(adjusted_rand_score(truth, labels))
    return result


def _main() -> int:
    import argparse

    from airframe.ml.features import extract_corpus

    ap = argparse.ArgumentParser(description="cluster failures into distinct bugs")
    ap.add_argument("--manifest", default="data/corpus_manifest.json")
    ap.add_argument("--eps", type=float, default=DEFAULT_EPS)
    ap.add_argument("--include-passes", action="store_true")
    args = ap.parse_args()

    features = extract_corpus(args.manifest, only_failures=not args.include_passes)
    print(f"loaded {len(features)} runs\n")
    print(cluster_failures(features, eps=args.eps).report())
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
