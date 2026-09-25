"""Flaky-test prediction.

A **flaky** test fails sometimes and passes sometimes on unchanged code. Flakes are
the most corrosive thing in a CI system: once a suite has a few, people stop reading
red builds, and then the suite stops finding real bugs. Distinguishing "this test is
unreliable" from "this code is broken" is therefore high-value work.

What makes this implementation unusual — and worth trusting
----------------------------------------------------------
Most flake detection is heuristic ("failed then passed on retry") because nobody has
labelled data. Here the simulator's probabilistic fault mode gives us **genuine
ground truth**: we know which runs had a 50%-probability fault injected, so we know
which tests are truly flaky and which are deterministic. That makes the classifier
*evaluable* — precision and recall are reported as measured numbers, not asserted.

So this module reports two things:

1. A **historical flake rate** per test, computed straight from stored results. Simple,
   exact, and what you should actually ship. No model needed.
2. A **classifier** predicting flakiness from a test's outcome pattern, evaluated
   honestly against ground truth.

Being clear about (1) versus (2) is the point. The statistical answer is better than
the ML answer for this problem, and saying so is more useful than pretending
otherwise — the classifier exists to demonstrate the method and to show what it buys
(prediction from few observations) and costs (opacity).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

#: A test needs at least this many observations before flakiness can be claimed.
#: One failure out of one run is not a flake rate, it is a failure.
MIN_OBSERVATIONS = 4

#: Above this historical rate a test is treated as flaky.
FLAKE_THRESHOLD = 0.10


@dataclass
class RunHistory:
    """Outcome history for one test, across runs.

    Named `RunHistory` rather than the more obvious `TestHistory` because pytest
    collects any class whose name begins with `Test`. A domain class that pytest tries
    to instantiate as a test suite emits a collection warning in every file that
    imports it — a small thing that makes a clean test run look untidy forever.
    """

    nodeid: str
    outcomes: list[bool] = field(default_factory=list)      # True = passed

    @property
    def runs(self) -> int:
        return len(self.outcomes)

    @property
    def pass_rate(self) -> float:
        return sum(self.outcomes) / self.runs if self.runs else 0.0

    @property
    def flake_rate(self) -> float:
        """Fraction of outcomes in the minority class.

        A test that always passes (or always fails) has rate 0 — it is deterministic.
        A test that passes half the time has rate 0.5. This captures "inconsistent"
        rather than "failing", which is the actual distinction.
        """
        if self.runs < 2:
            return 0.0
        passes = sum(self.outcomes)
        return min(passes, self.runs - passes) / self.runs

    @property
    def transitions(self) -> int:
        """How often the outcome flipped. Distinguishes alternating from clustered.

        Ten passes then ten failures is a regression (1 transition). Alternating
        pass/fail is a flake (19 transitions). Both have flake_rate 0.5, so this
        feature carries information the rate alone does not.
        """
        # strict=False is required, not incidental: this is the standard
        # consecutive-pairs idiom and the slice is deliberately one shorter.
        return sum(
            1 for a, b in zip(self.outcomes, self.outcomes[1:], strict=False) if a != b
        )

    @property
    def is_flaky(self) -> bool:
        """Genuinely flaky: inconsistent AND alternating.

        The `transitions` clause is load-bearing. A test that failed five times and
        then passed five times has flake_rate 0.5 but only ONE transition — that is a
        test someone FIXED, not a flaky test. Without this clause, every bug fix in
        the repository's history shows up in the flake leaderboard, which is both
        wrong and actively misleading. See BUILD_JOURNAL.md #19.
        """
        return (
            self.runs >= MIN_OBSERVATIONS
            and self.flake_rate >= FLAKE_THRESHOLD
            and self.transitions >= 2
        )

    @property
    def classification(self) -> str:
        """What this history actually shows.

        Distinguishing these four is the whole value of keeping history rather than
        just a latest-result. They are routinely conflated, and they call for
        completely different responses:

          stable     — always passed. Nothing to do.
          failing    — always failed. A real bug; fix the product.
          fixed      — failed, then passed, one transition. Somebody fixed it.
          regressed  — passed, then failed, one transition. Somebody broke it. URGENT.
          flaky      — alternates. Fix the TEST, not the product.
        """
        if self.runs < 2:
            return "stable" if self.pass_rate == 1.0 else "failing"
        if self.flake_rate == 0.0:
            return "stable" if self.pass_rate == 1.0 else "failing"
        if self.transitions >= 2 and self.flake_rate >= FLAKE_THRESHOLD:
            return "flaky"
        # Exactly one transition: a step change. Direction decides which kind.
        if self.transitions == 1:
            return "fixed" if self.outcomes[-1] else "regressed"
        return "flaky" if self.flake_rate >= FLAKE_THRESHOLD else "stable"

    def features(self) -> dict[str, float]:
        return {
            "runs": float(self.runs),
            "pass_rate": self.pass_rate,
            "flake_rate": self.flake_rate,
            "transitions": float(self.transitions),
            "transition_rate": self.transitions / max(self.runs - 1, 1),
            "longest_streak": float(self._longest_streak()),
        }

    def _longest_streak(self) -> int:
        best = current = 1
        for a, b in zip(self.outcomes, self.outcomes[1:], strict=False):
            current = current + 1 if a == b else 1
            best = max(best, current)
        return best if self.outcomes else 0

    def describe(self) -> str:
        pattern = "".join("." if ok else "F" for ok in self.outcomes[-40:])
        label = self.classification
        return (
            f"{label.upper() if label in ('flaky', 'regressed') else label:<9} "
            f"rate={self.flake_rate:.2f} runs={self.runs:<4} "
            f"transitions={self.transitions:<3} {pattern}  {self.nodeid}"
        )


FEATURE_NAMES = ("runs", "pass_rate", "flake_rate", "transitions",
                 "transition_rate", "longest_streak")


def histories_from_store(conn: sqlite3.Connection) -> list[RunHistory]:
    """Build per-test histories from stored results.

    Uses the *final* outcome per (run, test) so retries within one run count once —
    otherwise a test retried three times looks flakier than one retried none, purely
    because of the retry policy rather than the test's behaviour.
    """
    rows = conn.execute(
        """SELECT nodeid, run_id, outcome FROM v_final_results
           WHERE outcome IN ('passed', 'failed') ORDER BY run_id"""
    ).fetchall()

    by_test: dict[str, RunHistory] = {}
    for row in rows:
        history = by_test.setdefault(row["nodeid"], RunHistory(nodeid=row["nodeid"]))
        history.outcomes.append(row["outcome"] == "passed")
    return list(by_test.values())


def histories_from_corpus(manifest_path: str) -> tuple[list[RunHistory], dict[str, bool]]:
    """Build histories from the flake corpus, with ground-truth labels.

    Returns (histories, {nodeid: truly_flaky}). The simulator ran each fault with
    probability 0.5, so a probabilistic fault is genuinely flaky and a deterministic
    one genuinely is not — labels we can actually trust.
    """
    import json
    from pathlib import Path

    manifest = json.loads(Path(manifest_path).read_text())
    histories: dict[str, RunHistory] = {}
    truth: dict[str, bool] = {}

    # Probabilistic runs -> genuinely flaky pseudo-tests.
    for entry in manifest.get("flake", []):
        nodeid = f"flake::{entry['fault']}"
        histories.setdefault(nodeid, RunHistory(nodeid=nodeid)).outcomes.append(
            not entry["fired"]          # the fault firing means the test failed
        )
        truth[nodeid] = True

    # Deterministic runs -> genuinely stable pseudo-tests (always pass or always fail).
    for entry in manifest.get("deterministic", []):
        nodeid = f"deterministic::{entry['scenario']}::{entry['fault']}"
        ok = bool(entry["summary"]["result"]["ok"])
        histories.setdefault(nodeid, RunHistory(nodeid=nodeid)).outcomes.append(ok)
        truth[nodeid] = False

    return list(histories.values()), truth


#: Minimum positive examples in the held-out set for metrics to mean anything.
#: With one positive sample, precision and recall can only be 0.0 or 1.0, and a
#: reported "precision=1.00" carries no information whatsoever. Quoting such a
#: number without this caveat is the most common way ML results get oversold.
MIN_TEST_POSITIVES = 5


@dataclass
class FlakeModel:
    model: RandomForestClassifier
    precision: float
    recall: float
    f1: float
    n_train: int
    n_test: int
    n_test_positives: int = 0
    report_text: str = ""

    @property
    def metrics_are_trustworthy(self) -> bool:
        return self.n_test_positives >= MIN_TEST_POSITIVES

    def predict(self, history: RunHistory) -> tuple[bool, float]:
        """Returns (is_flaky, confidence)."""
        vector = np.array([[history.features()[n] for n in FEATURE_NAMES]])
        probability = float(self.model.predict_proba(vector)[0][1])
        return probability >= 0.5, probability

    def summary(self) -> str:
        line = (
            f"flake classifier: precision={self.precision:.2f} recall={self.recall:.2f} "
            f"f1={self.f1:.2f} (trained on {self.n_train}, tested on {self.n_test})"
        )
        if not self.metrics_are_trustworthy:
            line += (
                f"\n  WARNING: only {self.n_test_positives} flaky example(s) in the "
                f"held-out set (need {MIN_TEST_POSITIVES}). These metrics are NOT "
                "meaningful -- with so few positives, precision and recall can only be "
                "0.0 or 1.0. Treat this as a demonstration of the method, not as "
                "evidence that the model works."
            )
        return line


def train(
    histories: list[RunHistory], truth: dict[str, bool], *, random_state: int = 42
) -> FlakeModel | None:
    """Train and honestly evaluate a flake classifier.

    Returns None when there is not enough labelled data of both classes — a
    classifier trained on one class would report 100% accuracy and be worthless,
    which is the most common way ML results get oversold.
    """
    usable = [h for h in histories if h.nodeid in truth and h.runs >= 2]
    labels = [truth[h.nodeid] for h in usable]
    if len(usable) < 8 or len(set(labels)) < 2:
        return None

    X = np.array([[h.features()[n] for n in FEATURE_NAMES] for h in usable])
    y = np.array(labels, dtype=int)

    # Stratified split so both classes appear in train and test. Without it a small
    # dataset can put every flaky example in one side and the metrics become fiction.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=random_state, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200, random_state=random_state, class_weight="balanced"
    )
    model.fit(X_train, y_train)
    predicted = model.predict(X_test)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predicted, average="binary", zero_division=0
    )
    return FlakeModel(
        model=model,
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        n_train=len(X_train),
        n_test=len(X_test),
        n_test_positives=int(y_test.sum()),
        report_text=classification_report(
            y_test, predicted, target_names=["stable", "flaky"], zero_division=0
        ),
    )


def feature_importance(model: FlakeModel) -> list[tuple[str, float]]:
    """Which features the model relies on — the interpretability check.

    If `flake_rate` dominates (it should), the model has essentially rediscovered the
    statistical answer, and that is worth knowing rather than hiding: it tells you the
    ML layer is adding complexity without adding insight for this particular problem.
    """
    return sorted(
        # strict=True: one importance per feature. A mismatch means the model was
        # trained on a different feature set than we are naming, which would make
        # the whole report wrong rather than merely short.
        zip(FEATURE_NAMES, model.model.feature_importances_, strict=True),
        key=lambda kv: -kv[1],
    )


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="flaky-test analysis")
    ap.add_argument("--manifest", default="data/corpus_manifest.json")
    ap.add_argument("--from-store", action="store_true",
                    help="analyse real pytest history instead of the corpus")
    args = ap.parse_args()

    if args.from_store:
        from airframe.store import db as store

        conn = store.connect()
        try:
            histories = histories_from_store(conn)
        finally:
            conn.close()
        print(f"=== historical flake rates ({len(histories)} tests) ===")
        for h in sorted(histories, key=lambda x: -x.flake_rate)[:25]:
            print("  " + h.describe())
        return 0

    histories, truth = histories_from_corpus(args.manifest)
    flaky = [h for h in histories if truth.get(h.nodeid)]
    stable = [h for h in histories if not truth.get(h.nodeid)]
    print(f"=== corpus: {len(flaky)} genuinely flaky, {len(stable)} genuinely stable ===\n")

    print("statistical detection (flake_rate threshold):")
    tp = sum(1 for h in flaky if h.is_flaky)
    fp = sum(1 for h in stable if h.is_flaky)
    fn = len(flaky) - tp
    print(f"  true positives={tp}  false positives={fp}  false negatives={fn}")
    if tp + fp:
        print(f"  precision={tp / (tp + fp):.2f}  recall={tp / max(tp + fn, 1):.2f}")
    print()

    for h in sorted(histories, key=lambda x: -x.flake_rate)[:12]:
        print("  " + h.describe())

    print()
    model = train(histories, truth)
    if model is None:
        print("classifier: not enough labelled data of both classes")
        return 0
    print(model.summary())
    print()
    print(model.report_text)
    print("feature importance:")
    for name, importance in feature_importance(model):
        print(f"  {name:<18} {importance:.3f}")
    print()
    print("Verdict on this model: the statistical flake_rate threshold above achieves")
    print("the same result with no model, no training and full explainability. For THIS")
    print("problem the simple answer is the better answer; the classifier is here to")
    print("demonstrate the method and to make that comparison explicit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
