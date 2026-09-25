"""Timeline correlation — logs, packets and KPIs on one clock.

This is the artifact that makes a root cause obvious, and it is the single most
useful thing in the analysis stack. Individually each source is ambiguous:

* the **log** says the handshake timed out, but not whether the AP ever replied,
* the **capture** shows M2 retransmitted four times, but not what the supplicant
  believed was happening,
* the **KPI** samples show latency spiking, but not why.

Interleaved on one monotonic clock, the causal order becomes visible — and causal
order is what separates "these things both happened" from "this caused that".

The whole approach depends on a shared clock, which is why the simulator anchors its
`VirtualClock` and its pcap timestamps to the same fixed epoch. Correlating two
sources whose clocks differ by an unknown offset is guesswork; correlating two
sources that share a clock is arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from airframe.logs.parse import LogLine, parse_file
from airframe.pcap.dissect import Capture, Frame, load_capture


class Source(str, Enum):
    LOG = "log"
    FRAME = "frame"
    KPI = "kpi"
    MARKER = "marker"


@dataclass
class Event:
    """One thing that happened, from any source."""

    monotonic_ms: int
    source: Source
    label: str
    detail: str = ""
    severity: str = "info"          # info | warning | error
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.severity == "error"


@dataclass
class Timeline:
    events: list[Event]
    log_count: int = 0
    frame_count: int = 0
    kpi_count: int = 0

    def __len__(self) -> int:
        return len(self.events)

    @property
    def duration_ms(self) -> int:
        if not self.events:
            return 0
        return self.events[-1].monotonic_ms - self.events[0].monotonic_ms

    def errors(self) -> list[Event]:
        return [e for e in self.events if e.is_error]

    def around(self, monotonic_ms: int, window_ms: int = 500) -> list[Event]:
        """Events near a point in time — the "what else was happening" query.

        This is the primary way the timeline gets used during triage: find the first
        error, then look at what surrounded it.
        """
        lo, hi = monotonic_ms - window_ms, monotonic_ms + window_ms
        return [e for e in self.events if lo <= e.monotonic_ms <= hi]

    def first_error_context(self, window_ms: int = 800) -> list[Event]:
        """Everything around the first error. Usually where the root cause lives."""
        errors = self.errors()
        if not errors:
            return []
        return self.around(errors[0].monotonic_ms, window_ms)

    def render(self, limit: int = 120, *, width: int = 100) -> str:
        """ASCII timeline. Source column makes the interleaving legible at a glance."""
        if not self.events:
            return "(empty timeline)"

        glyph = {Source.LOG: "log ", Source.FRAME: "pkt ",
                 Source.KPI: "kpi ", Source.MARKER: "--->"}
        mark = {"info": " ", "warning": "!", "error": "X"}

        lines = [
            f"timeline: {len(self.events)} events over {self.duration_ms}ms "
            f"({self.log_count} log, {self.frame_count} frame, {self.kpi_count} kpi)",
            "-" * width,
        ]
        shown = self.events[:limit]
        for e in shown:
            text = f"{e.label} {e.detail}".strip()
            budget = width - 22
            if len(text) > budget:
                text = text[: budget - 1] + "…"
            lines.append(
                f"{e.monotonic_ms:>8}ms {mark[e.severity]} {glyph[e.source]} {text}"
            )
        if len(self.events) > limit:
            lines.append(f"... {len(self.events) - limit} more events")
        return "\n".join(lines)


# ---------------------------------------------------------------- builders


def _log_events(lines: list[LogLine]) -> list[Event]:
    out: list[Event] = []
    for line in lines:
        severity = "error" if line.level == "ERROR" else (
            "warning" if line.level == "WARN" else "info"
        )
        out.append(
            Event(
                monotonic_ms=line.monotonic_ms,
                source=Source.LOG,
                label=f"{line.component}:",
                detail=line.message,
                severity=severity,
                fields=line.fields,
            )
        )
    return out


def _frame_events(cap: Capture, *, collapse_data: bool = True) -> list[Event]:
    """Frames as events.

    Data frames are collapsed into periodic summaries rather than listed
    individually: a 500-frame capture would otherwise bury the eight management
    frames that actually explain the failure. Keeping every data frame would be
    "complete" and useless — the point of a timeline is to be readable.
    """
    out: list[Event] = []
    data_bucket: list[Frame] = []
    bucket_start = 0

    def flush() -> None:
        if not data_bucket:
            return
        retries = sum(1 for f in data_bucket if f.retry)
        out.append(
            Event(
                monotonic_ms=bucket_start,
                source=Source.FRAME,
                label=f"data x{len(data_bucket)}",
                detail=f"retries={retries} ({retries / len(data_bucket):.0%})",
                severity="warning" if retries / len(data_bucket) > 0.2 else "info",
            )
        )
        data_bucket.clear()

    for frame in cap:
        ms = int(frame.time_s * 1000)
        is_data = frame.ftype == 2 and not frame.is_eapol

        if is_data and collapse_data:
            if not data_bucket:
                bucket_start = ms
            data_bucket.append(frame)
            # Flush every second so congestion shows up as it develops.
            if ms - bucket_start >= 1000:
                flush()
            continue

        flush()
        severity = "info"
        detail_bits = []
        if frame.status_code is not None:
            detail_bits.append(f"status={frame.status_code}")
            if frame.status_code != 0:
                severity = "error"
        if frame.reason_code is not None:
            detail_bits.append(f"reason={frame.reason_code}")
            severity = "error" if frame.reason_code not in (3, 8) else "warning"
        if frame.ssid:
            detail_bits.append(f'ssid="{frame.ssid}"')
        if frame.retry:
            detail_bits.append("RETRY")
            severity = "warning"
        if frame.rssi_dbm is not None:
            detail_bits.append(f"rssi={frame.rssi_dbm}")

        out.append(
            Event(
                monotonic_ms=ms,
                source=Source.FRAME,
                label=frame.kind.value,
                detail=" ".join(detail_bits),
                severity=severity,
            )
        )
    flush()
    return out


def build(
    *,
    log_path: str | Path | None = None,
    pcap_path: str | Path | None = None,
    kpi_samples: list[tuple[int, str, float, str]] | None = None,
    log_lines: list[LogLine] | None = None,
) -> Timeline:
    """Merge available sources into one ordered timeline.

    Every source is optional — a real triage often has logs but no capture, or a
    capture but no KPI data, and the function must produce the best available
    picture rather than requiring all three.
    """
    events: list[Event] = []
    log_count = frame_count = kpi_count = 0

    lines = log_lines
    if lines is None and log_path is not None and Path(log_path).exists():
        lines = parse_file(log_path)
    if lines:
        log_events = _log_events(lines)
        events.extend(log_events)
        log_count = len(log_events)

    if pcap_path is not None and Path(pcap_path).exists():
        cap = load_capture(pcap_path)
        frame_events = _frame_events(cap)
        events.extend(frame_events)
        frame_count = len(frame_events)

    for ms, probe, value, unit in kpi_samples or []:
        events.append(
            Event(monotonic_ms=ms, source=Source.KPI, label=probe,
                  detail=f"{value:.2f}{unit}")
        )
        kpi_count += 1

    # Stable sort: at an identical timestamp, show the packet before the log line
    # that describes it, because the frame is the cause and the log is the effect.
    order = {Source.FRAME: 0, Source.KPI: 1, Source.LOG: 2, Source.MARKER: 3}
    events.sort(key=lambda e: (e.monotonic_ms, order[e.source]))

    return Timeline(events=events, log_count=log_count,
                    frame_count=frame_count, kpi_count=kpi_count)


def build_from_tag(data_dir: str | Path, tag: str) -> Timeline:
    """Build a timeline from a corpus tag (e.g. `wpa2_FOURWAY_M3_TIMEOUT_1013`)."""
    root = Path(data_dir)
    return build(log_path=root / "logs" / f"{tag}.log",
                 pcap_path=root / "pcaps" / f"{tag}.pcap")


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="render a correlated timeline")
    ap.add_argument("--log")
    ap.add_argument("--pcap")
    ap.add_argument("--tag", help="corpus tag, resolves both files under data/")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--limit", type=int, default=120)
    ap.add_argument("--errors", action="store_true", help="only the first error's context")
    args = ap.parse_args()

    timeline = (
        build_from_tag(args.data_dir, args.tag) if args.tag
        else build(log_path=args.log, pcap_path=args.pcap)
    )

    if args.errors:
        context = timeline.first_error_context()
        if not context:
            print("no errors in this timeline")
            return 0
        print(f"context around the first error ({len(context)} events):\n")
        print(Timeline(events=context).render(limit=args.limit))
    else:
        print(timeline.render(limit=args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
