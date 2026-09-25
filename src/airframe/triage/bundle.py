"""Failure bundles — the context an LLM actually needs.

This module is **context engineering**, and it is where most of the quality of an
LLM-based triage system lives. The naive approach is to paste the whole log into the
prompt. That fails for three separate reasons:

1. **Cost and latency** scale with tokens, and a run produces thousands of lines.
2. **Signal gets diluted.** Models attend worse to a needle in 4,000 lines of
   boilerplate than to a needle in 40 lines of curated evidence. More context is not
   monotonically better.
3. **It throws away analysis we already did.** The pcap forensics, the mined log
   templates, the correlated timeline and the failure cluster are all *higher-order*
   facts than raw log lines. Making the model re-derive them from raw text is asking
   it to redo work that deterministic code already did correctly.

So a bundle contains, within a token budget:

* test identity and the injected fault (when known)
* the **forensics verdict** from the packet capture
* **mined log templates** rather than raw lines — 40 templates, not 4,000 lines
* the **error window** from the correlated timeline: what happened around the failure
* **KPI deltas** against baseline
* the **cluster** it belongs to and similar historical failures

The model's job is then judgement and synthesis across sources, which is what it is
good at — not string parsing, which it is worse at than a regex.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airframe.logs.drain import DrainMiner
from airframe.logs.parse import LogLine, parse_file, summarise
from airframe.logs.timeline import Timeline, build
from airframe.pcap.anomaly import scan_capture
from airframe.pcap.assoc import Forensics, analyse
from airframe.pcap.dissect import load_capture

#: Token budget for the whole bundle, approximated at 4 characters per token. Kept
#: well under typical context limits so the model has room to reason and to make tool
#: calls, rather than spending its whole window on input.
DEFAULT_BUDGET_TOKENS = 3000
CHARS_PER_TOKEN = 4

#: Cap on log-template lines included. Beyond this the tail is boilerplate.
MAX_TEMPLATES = 25

#: Timeline events around the first error. Wide enough for causality, tight enough
#: to stay legible.
ERROR_WINDOW_MS = 1200
MAX_TIMELINE_EVENTS = 30


@dataclass
class FailureBundle:
    tag: str
    nodeid: str = ""
    injected_fault: str | None = None
    forensics: Forensics | None = None
    log_templates: list[str] = field(default_factory=list)
    error_window: list[str] = field(default_factory=list)
    pcap_anomalies: list[str] = field(default_factory=list)
    kpi_deltas: list[str] = field(default_factory=list)
    cluster_id: int | None = None
    cluster_size: int = 0
    similar_failures: list[str] = field(default_factory=list)
    log_summary: str = ""
    truncated: bool = False

    #: Paths kept so the agent's tools can fetch more detail on demand. This is the
    #: key structural idea: the bundle is a *summary*, and the agent can drill in
    #: where it needs to rather than everything being pushed up front.
    log_path: str | None = None
    pcap_path: str | None = None

    def render(self, budget_tokens: int = DEFAULT_BUDGET_TOKENS) -> str:
        """Render to text, trimming lowest-value sections first if over budget."""
        sections: list[tuple[str, str]] = []

        header = [f"FAILURE: {self.tag}"]
        if self.nodeid:
            header.append(f"test: {self.nodeid}")
        sections.append(("header", "\n".join(header)))

        if self.forensics:
            f = self.forensics
            lines = [
                "## PACKET CAPTURE FORENSICS",
                f"stage reached : {f.stage_reached.value}",
                f"outcome       : {'SUCCESS' if f.succeeded else 'FAILURE'}",
            ]
            if f.failed_at:
                lines.append(f"failed at     : {f.failed_at.value}")
            if f.reason_code is not None:
                lines.append(f"reason code   : {f.reason_code}")
            if f.status_code:
                lines.append(f"status code   : {f.status_code}")
            if f.akm:
                lines.append(f"security (AKM): {f.akm}")
            lines.append(f"verdict       : {f.verdict}")
            if f.eapol_seen:
                lines.append(f"EAPOL         : {' '.join(f.eapol_seen)}")
            lines.append(f"retry rate    : {f.retry_rate:.1%}")
            if f.rssi_first is not None:
                lines.append(f"RSSI          : {f.rssi_first} -> {f.rssi_last} dBm")
            if f.timings:
                lines.append("stage timings :")
                lines.extend(f"  {t.name}: {t.duration_ms}ms" for t in f.timings)
            if f.evidence:
                lines.append("evidence      :")
                lines.extend(f"  - {e}" for e in f.evidence)
            sections.append(("forensics", "\n".join(lines)))

        if self.error_window:
            sections.append((
                "error_window",
                "## CORRELATED TIMELINE AROUND THE FIRST ERROR\n"
                + "\n".join(self.error_window),
            ))

        if self.pcap_anomalies:
            sections.append((
                "anomalies",
                "## PACKET ANOMALIES DETECTED\n" + "\n".join(f"- {a}" for a in self.pcap_anomalies),
            ))

        if self.log_summary:
            sections.append(("log_summary", "## LOG SUMMARY\n" + self.log_summary))

        if self.log_templates:
            sections.append((
                "templates",
                "## LOG TEMPLATES (mined, most frequent first)\n"
                + "\n".join(self.log_templates),
            ))

        if self.kpi_deltas:
            sections.append((
                "kpi",
                "## NETWORK KPI vs BASELINE\n" + "\n".join(f"- {d}" for d in self.kpi_deltas),
            ))

        if self.cluster_id is not None:
            block = [
                "## FAILURE CLUSTER",
                f"this failure belongs to cluster {self.cluster_id} "
                f"({self.cluster_size} similar failures in this run)",
            ]
            if self.similar_failures:
                block.append("similar: " + ", ".join(self.similar_failures[:5]))
            sections.append(("cluster", "\n".join(block)))

        # Trim from the least valuable end if over budget. Order is deliberate: the
        # forensics verdict and the error window are the highest-signal sections and
        # are dropped last; template lists and KPI tables go first.
        priority = ["templates", "kpi", "log_summary", "anomalies", "cluster",
                    "error_window", "forensics", "header"]
        budget_chars = budget_tokens * CHARS_PER_TOKEN
        kept = dict(sections)
        order = [name for name, _ in sections]

        def total() -> int:
            return sum(len(kept[n]) for n in order if n in kept)

        for name in priority:
            if total() <= budget_chars:
                break
            if name in kept and name not in ("header", "forensics"):
                del kept[name]
                self.truncated = True

        return "\n\n".join(kept[n] for n in order if n in kept)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tag": self.tag,
            "nodeid": self.nodeid,
            "injected_fault": self.injected_fault,
            "cluster_id": self.cluster_id,
            "verdict": self.forensics.verdict if self.forensics else None,
            "truncated": self.truncated,
        }


def _timeline_window(timeline: Timeline) -> list[str]:
    events = timeline.first_error_context(ERROR_WINDOW_MS)
    if not events:
        events = timeline.events[-MAX_TIMELINE_EVENTS:]
    out: list[str] = []
    for e in events[:MAX_TIMELINE_EVENTS]:
        marker = {"info": " ", "warning": "!", "error": "X"}[e.severity]
        out.append(f"{e.monotonic_ms:>8}ms {marker} [{e.source.value:<5}] "
                   f"{e.label} {e.detail}".rstrip())
    return out


def build_bundle(
    *,
    tag: str,
    log_path: str | Path | None = None,
    pcap_path: str | Path | None = None,
    nodeid: str = "",
    injected_fault: str | None = None,
    kpi_deltas: list[str] | None = None,
    cluster_id: int | None = None,
    cluster_size: int = 0,
    similar_failures: list[str] | None = None,
) -> FailureBundle:
    """Assemble a bundle from whatever artifacts exist."""
    bundle = FailureBundle(
        tag=tag,
        nodeid=nodeid,
        injected_fault=injected_fault,
        kpi_deltas=kpi_deltas or [],
        cluster_id=cluster_id,
        cluster_size=cluster_size,
        similar_failures=similar_failures or [],
        log_path=str(log_path) if log_path else None,
        pcap_path=str(pcap_path) if pcap_path else None,
    )

    lines: list[LogLine] = []
    if log_path and Path(log_path).exists():
        lines = parse_file(log_path)
        summary = summarise(lines)
        bundle.log_summary = summary.describe()

        # Mine templates from THIS run's logs. Per-run mining is right here (unlike
        # the ML layer, which needs globally consistent ids) because the goal is a
        # readable digest rather than a comparable feature vector.
        miner = DrainMiner()
        for line in lines:
            miner.add(line.message)
        bundle.log_templates = [
            f"  x{t.hits:<4} {t.text}" for t in miner.templates[:MAX_TEMPLATES]
        ]

    if pcap_path and Path(pcap_path).exists():
        cap = load_capture(pcap_path)
        bundle.forensics = analyse(cap)
        bundle.pcap_anomalies = [str(a) for a in scan_capture(cap)]

    timeline = build(log_lines=lines or None, pcap_path=pcap_path)
    bundle.error_window = _timeline_window(timeline)
    return bundle


def build_from_tag(tag: str, data_dir: str | Path = "data", **kwargs: Any) -> FailureBundle:
    root = Path(data_dir)
    return build_bundle(
        tag=tag,
        log_path=root / "logs" / f"{tag}.log",
        pcap_path=root / "pcaps" / f"{tag}.pcap",
        **kwargs,
    )


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="build a failure bundle")
    ap.add_argument("tag")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET_TOKENS)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    bundle = build_from_tag(args.tag, args.data_dir)
    if args.json:
        print(json.dumps(bundle.as_dict(), indent=2))
        return 0
    text = bundle.render(args.budget)
    print(text)
    print(f"\n--- {len(text)} chars ~= {len(text) // CHARS_PER_TOKEN} tokens"
          f"{' (TRUNCATED)' if bundle.truncated else ''} ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
