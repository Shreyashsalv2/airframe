"""Feature extraction — turning a test failure into a vector.

This is the least glamorous and most decisive part of any ML pipeline. Model choice
is nearly irrelevant next to feature quality: good features make a trivial model
work, and bad features make no model work.

Two representations are built, because the two downstream tasks want different
things:

* **A text signature** — the failure rendered as a bag of stable tokens, for
  TF-IDF clustering. Deliberately excludes anything run-specific (timestamps,
  MAC addresses, IP addresses, seeds), because if those survive then every failure
  is unique and the clustering learns nothing. Getting this exclusion right *is*
  the clustering algorithm; the DBSCAN call afterwards is three lines.

* **A numeric vector** — stage timings, frame counts, codes and rates, for anomaly
  detection and the flake classifier.

The guiding rule: **a feature must be invariant across runs of the same bug.** Two
M3 timeouts on different BSSIDs at different times are the same bug and must produce
near-identical features. If they do not, no amount of modelling will group them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from airframe.logs.drain import DrainMiner
from airframe.logs.parse import LogLine, parse_file, summarise
from airframe.pcap.assoc import Forensics, analyse
from airframe.pcap.dissect import Capture, load_capture

#: Substrings scrubbed from the text signature. Every one of these varies between
#: runs of the *same* bug, so leaving any of them in guarantees singleton clusters.
VOLATILE = (
    re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"),   # MAC
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),      # IP
    re.compile(r"\b\d{4}-\d{2}-\d{2}T[\d:.]+Z?\b"),             # timestamp
    re.compile(r"elapsed_ms=\d+"),
    re.compile(r"timeout_ms=\d+"),
    re.compile(r"total_ms=\d+"),
    re.compile(r"\bseed=\d+"),
    re.compile(r"\baid=\d+"),
    re.compile(r"\breplay=\d+"),
    re.compile(r"\brssi=-?\d+"),
)

#: Numeric feature names, fixed and ordered so a vector is interpretable and so
#: train/predict can never silently disagree about column meaning.
NUMERIC_FEATURES: tuple[str, ...] = (
    "scan_ms", "auth_ms", "assoc_ms", "fourway_ms", "dhcp_ms", "total_ms",
    "n_frames", "n_mgmt_frames", "n_data_frames", "n_eapol",
    "eapol_m1", "eapol_m2", "eapol_m3", "eapol_m4",
    "n_deauth", "n_retries", "retry_rate",
    "rssi_first", "rssi_last", "rssi_drop",
    "status_code", "reason_code",
    "n_log_lines", "n_errors", "n_warnings", "n_transitions",
    "reached_auth", "reached_assoc", "reached_keyed", "reached_data",
)


def scrub(text: str) -> str:
    """Remove run-specific detail, keeping the shape of the message."""
    for pattern in VOLATILE:
        text = pattern.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


@dataclass
class FailureFeatures:
    """Both representations of one failure, plus the labels used for evaluation."""

    tag: str
    signature: str                                   # text, for clustering
    numeric: dict[str, float] = field(default_factory=dict)
    template_histogram: dict[int, int] = field(default_factory=dict)
    #: Ground truth, available because the simulator injected a known fault. This is
    #: a rare luxury: it makes the clustering evaluable rather than merely plausible.
    injected_fault: str | None = None
    verdict: str = ""
    failed_stage: str = ""

    def vector(self) -> list[float]:
        return [self.numeric.get(name, 0.0) for name in NUMERIC_FEATURES]


def _stage_flags(report: Forensics) -> dict[str, float]:
    from airframe.pcap.assoc import Stage

    rank = report.stage_reached.rank
    return {
        "reached_auth": 1.0 if rank >= Stage.AUTHENTICATED.rank else 0.0,
        "reached_assoc": 1.0 if rank >= Stage.ASSOCIATED.rank else 0.0,
        "reached_keyed": 1.0 if rank >= Stage.KEYED.rank else 0.0,
        "reached_data": 1.0 if rank >= Stage.DATA.rank else 0.0,
    }


def extract(
    *,
    tag: str,
    log_path: str | Path | None = None,
    pcap_path: str | Path | None = None,
    injected_fault: str | None = None,
    miner: DrainMiner | None = None,
) -> FailureFeatures:
    """Build features for one run from its artifacts."""
    lines: list[LogLine] = []
    if log_path and Path(log_path).exists():
        lines = parse_file(log_path)

    cap: Capture | None = None
    report: Forensics | None = None
    if pcap_path and Path(pcap_path).exists():
        cap = load_capture(pcap_path)
        report = analyse(cap)

    numeric: dict[str, float] = {}
    signature_parts: list[str] = []

    # ---- from the logs ----
    if lines:
        summary = summarise(lines)
        numeric.update({
            "n_log_lines": float(summary.total),
            "n_errors": float(summary.by_level.get("ERROR", 0)),
            "n_warnings": float(summary.by_level.get("WARN", 0)),
            "n_transitions": float(len(summary.state_transitions)),
        })
        if summary.reason_codes:
            numeric["reason_code"] = float(summary.reason_codes[-1])
        if summary.status_codes:
            numeric["status_code"] = float(summary.status_codes[-1])

        # Error and warning messages carry nearly all the discriminative signal, so
        # the signature is built from those plus the state path. Including every INFO
        # line would swamp the distinguishing tokens with boilerplate that is
        # identical across all failures.
        for line in lines:
            if line.level in ("ERROR", "WARN"):
                signature_parts.append(scrub(line.message))
        if summary.final_state:
            signature_parts.append(f"final_state:{summary.final_state}")
        # The state path is a compact, highly discriminative feature: two runs that
        # took the same path through the machine failed in the same place.
        if summary.state_transitions:
            signature_parts.append(
                "path:" + ">".join(t[2] for t in summary.state_transitions[-6:])
            )

    # ---- from the capture ----
    if cap is not None and report is not None:
        counts = cap.counts()
        numeric.update({
            "n_frames": float(len(cap)),
            "n_mgmt_frames": float(sum(1 for f in cap if f.is_management)),
            "n_data_frames": float(sum(1 for f in cap if f.ftype == 2)),
            "n_eapol": float(sum(1 for f in cap if f.is_eapol)),
            "eapol_m1": float(counts.get("eapol_m1", 0)),
            "eapol_m2": float(counts.get("eapol_m2", 0)),
            "eapol_m3": float(counts.get("eapol_m3", 0)),
            "eapol_m4": float(counts.get("eapol_m4", 0)),
            "n_deauth": float(counts.get("deauth", 0) + counts.get("disassoc", 0)),
            "n_retries": float(sum(1 for f in cap if f.retry)),
            "retry_rate": float(cap.retry_rate),
        })
        rssi = cap.rssi_values
        if rssi:
            numeric.update({
                "rssi_first": float(rssi[0]),
                "rssi_last": float(rssi[-1]),
                "rssi_drop": float(rssi[0] - rssi[-1]),
            })
        for timing in report.timings:
            key = {
                "scan": "scan_ms", "authentication": "auth_ms",
                "association": "assoc_ms", "4-way handshake": "fourway_ms",
            }.get(timing.name)
            if key:
                numeric[key] = float(timing.duration_ms)
        numeric["total_ms"] = float(report.duration_s * 1000)
        numeric.update(_stage_flags(report))

        if report.reason_code is not None:
            numeric["reason_code"] = float(report.reason_code)
        if report.status_code is not None:
            numeric["status_code"] = float(report.status_code)

        # The forensics verdict is a strong signature component: it already encodes
        # the analyst's conclusion in stable language.
        signature_parts.append(f"stage:{report.stage_reached.value}")
        # Only the FIRST clause of the verdict. The full prose is long and largely
        # identical across every successful-but-degraded run, so including it diluted
        # the discriminative tokens under char n-gram similarity: three different
        # faults scored as near-duplicates because they shared 120 characters of
        # boilerplate. Short, high-signal tokens cluster far better than sentences.
        signature_parts.append(scrub(report.verdict.split(":")[0].split("—")[0])[:90])
        # Explicit degradation tokens. These faults connect successfully and differ
        # only in HOW the link behaved, so the difference has to be stated rather
        # than left implicit in a numeric field the text clusterer never sees.
        if numeric.get("retry_rate", 0.0) > 0.15:
            signature_parts.append("degraded_high_retry")
        if numeric.get("rssi_last", 0.0) and numeric["rssi_last"] < -80:
            signature_parts.append("degraded_weak_signal")
        if numeric.get("rssi_drop", 0.0) > 12:
            signature_parts.append("degraded_rssi_collapse")
        # EAPOL shape as discrete tokens: "m2x4 no_m3" is a highly distinctive
        # fingerprint that a numeric count expresses much more weakly.
        if numeric.get("eapol_m2", 0) > 1:
            signature_parts.append(f"m2_retransmit_x{int(numeric['eapol_m2'])}")
        if numeric.get("eapol_m1", 0) and not numeric.get("eapol_m3", 0):
            signature_parts.append("missing_m3")
        if numeric.get("eapol_m3", 0) and not numeric.get("eapol_m4", 0):
            signature_parts.append("missing_m4")

    histogram: dict[int, int] = {}
    if miner is not None and lines:
        histogram = miner.histogram([line.message for line in lines])

    return FailureFeatures(
        tag=tag,
        signature=" ".join(p for p in signature_parts if p),
        numeric=numeric,
        template_histogram=histogram,
        injected_fault=injected_fault,
        verdict=report.verdict if report else "",
        failed_stage=(report.failed_at.value if report and report.failed_at else ""),
    )


def extract_corpus(
    manifest_path: str | Path, *, only_failures: bool = False
) -> list[FailureFeatures]:
    """Extract features for every run in the corpus manifest."""
    import json

    manifest = json.loads(Path(manifest_path).read_text())
    miner = DrainMiner()

    entries = manifest.get("deterministic", [])
    # Fit the miner over the whole corpus first, so template ids are consistent
    # across runs. Mining per-run would give each run its own numbering and make the
    # histograms incomparable — a subtle bug that produces plausible garbage.
    for entry in entries:
        log = Path(entry["log"])
        if log.exists():
            for line in parse_file(log):
                miner.add(line.message)

    out: list[FailureFeatures] = []
    for entry in entries:
        features = extract(
            tag=entry["tag"],
            log_path=entry["log"],
            pcap_path=entry["pcap"],
            injected_fault=entry["fault"],
            miner=miner,
        )
        if only_failures and entry["fault"] == "NONE":
            continue
        out.append(features)
    return out


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="extract failure features")
    ap.add_argument("--manifest", default="data/corpus_manifest.json")
    ap.add_argument("--limit", type=int, default=6)
    args = ap.parse_args()

    features = extract_corpus(args.manifest)
    print(f"{len(features)} runs, {len(NUMERIC_FEATURES)} numeric features each\n")
    for f in features[: args.limit]:
        print(f"{f.tag}  (injected: {f.injected_fault})")
        print(f"  signature: {f.signature[:150]}")
        print(f"  templates: {len(f.template_histogram)} distinct")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
