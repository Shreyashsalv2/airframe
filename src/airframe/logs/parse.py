"""Log parsing — normalise wireless logs from different sources into one schema.

Two producers, one schema:

* the **simulator's** `wifid`-style output, which we designed, and
* **real macOS unified logging** (`log show --predicate 'subsystem == "com.apple.wifi"'`),
  which we did not.

Normalising both into the same `LogLine` is what lets the analysis layers above be
written once. The monotonic millisecond column is the important field: it is the
clock every layer correlates on (logs, pcap frames, KPI samples), and unlike a
wall-clock timestamp it never steps backwards.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# The simulator's format, which is fixed-width by design so it stays greppable:
#   2025-01-01T00:00:01.240Z [   1240ms] <NOTICE> wifid     : assoc resp status=0 ...
SIM_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+"
    r"\[\s*(?P<mono>\d+)ms\]\s+"
    r"<(?P<level>\w+)\s*>\s+"
    r"(?P<component>\S+?)\s*:\s+"
    r"(?P<message>.*)$"
)

# macOS `log show --style compact`:
#   2026-09-25 14:32:01.123 Df wifid[123:456] [com.apple.wifi:Client] message
MACOS_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} [\d:.]+)\s+"
    r"(?P<flag>\S+)\s+"
    r"(?P<component>[A-Za-z0-9_.-]+)"
    r"(?:\[[\d:]+\])?\s*"
    r"(?:\[(?P<subsystem>[^\]]*)\]\s*)?"
    r"(?P<message>.*)$"
)

#: macOS log level abbreviations.
MACOS_LEVELS = {"Df": "DEBUG", "I": "INFO", "Nt": "NOTICE", "Er": "ERROR",
                "Wn": "WARN", "Ft": "ERROR", "<Notice>": "NOTICE"}

#: key=value pairs, the reason the simulator formats messages the way it does:
#: structured fields survive template mining, interpolated prose does not.
KV_PAIR = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


@dataclass
class LogLine:
    raw: str
    message: str
    monotonic_ms: int = 0
    timestamp: str | None = None
    level: str = "INFO"
    component: str = "unknown"
    fields: dict[str, str] = field(default_factory=dict)
    source: str = "sim"

    @property
    def is_error(self) -> bool:
        return self.level in ("ERROR", "WARN")

    def get_int(self, key: str, default: int | None = None) -> int | None:
        try:
            return int(self.fields[key])
        except (KeyError, ValueError):
            return default

    def __str__(self) -> str:
        return f"[{self.monotonic_ms:>7}ms] {self.level:<6} {self.component:<11} {self.message}"


def extract_fields(message: str) -> dict[str, str]:
    """Pull `key=value` pairs out of a message body."""
    return {k: v.strip('"') for k, v in KV_PAIR.findall(message)}


def parse_sim_line(raw: str) -> LogLine | None:
    m = SIM_LINE.match(raw.rstrip("\n"))
    if not m:
        return None
    message = m.group("message")
    return LogLine(
        raw=raw.rstrip("\n"),
        message=message,
        monotonic_ms=int(m.group("mono")),
        timestamp=m.group("ts"),
        level=m.group("level").strip(),
        component=m.group("component"),
        fields=extract_fields(message),
        source="sim",
    )


def parse_macos_line(raw: str, epoch: datetime | None = None) -> LogLine | None:
    m = MACOS_LINE.match(raw.rstrip("\n"))
    if not m:
        return None
    message = m.group("message")

    # Derive a monotonic offset from the first line's timestamp, so real logs share
    # the same correlation clock as the simulator's.
    mono = 0
    ts_text = m.group("ts")
    try:
        parsed = datetime.strptime(ts_text, "%Y-%m-%d %H:%M:%S.%f")
        if epoch is not None:
            mono = int((parsed - epoch).total_seconds() * 1000)
    except ValueError:
        parsed = None

    return LogLine(
        raw=raw.rstrip("\n"),
        message=message,
        monotonic_ms=max(mono, 0),
        timestamp=ts_text,
        level=MACOS_LEVELS.get(m.group("flag"), "INFO"),
        component=m.group("component") or (m.group("subsystem") or "unknown"),
        fields=extract_fields(message),
        source="macos",
    )


def parse_lines(lines: Iterator[str] | list[str]) -> list[LogLine]:
    """Parse a mixed stream, auto-detecting each line's format.

    Unparseable lines are kept with `monotonic_ms` carried forward from the previous
    line rather than discarded. Dropping them would be convenient and wrong: a
    multi-line traceback or a stack dump is exactly the content you most want when
    triaging, and it never matches a line regex.
    """
    out: list[LogLine] = []
    macos_epoch: datetime | None = None
    last_mono = 0

    for raw in lines:
        if not raw.strip():
            continue

        parsed = parse_sim_line(raw)
        if parsed is None:
            m = MACOS_LINE.match(raw.rstrip("\n"))
            if m and macos_epoch is None:
                try:
                    macos_epoch = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    macos_epoch = None
            parsed = parse_macos_line(raw, macos_epoch)

        if parsed is None:
            parsed = LogLine(
                raw=raw.rstrip("\n"),
                message=raw.strip(),
                monotonic_ms=last_mono,
                level="INFO",
                component="unparsed",
                source="unknown",
            )
        last_mono = parsed.monotonic_ms
        out.append(parsed)
    return out


def parse_file(path: str | Path) -> list[LogLine]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"log file not found: {p}")
    return parse_lines(p.read_text(errors="replace").splitlines())


# ---------------------------------------------------------------- derived facts


@dataclass
class LogSummary:
    total: int
    by_level: dict[str, int]
    by_component: dict[str, int]
    errors: list[LogLine]
    duration_ms: int
    state_transitions: list[tuple[int, str, str]]   # (monotonic_ms, from, to)
    final_state: str | None
    reason_codes: list[int]
    status_codes: list[int]

    def describe(self) -> str:
        lines = [
            f"{self.total} lines over {self.duration_ms}ms",
            f"levels: {self.by_level}",
            f"components: {self.by_component}",
        ]
        if self.state_transitions:
            path = " -> ".join(
                [self.state_transitions[0][1]] + [t[2] for t in self.state_transitions]
            )
            lines.append(f"state path: {path}")
        if self.reason_codes:
            lines.append(f"reason codes: {self.reason_codes}")
        if self.errors:
            lines.append(f"first error: {self.errors[0].message[:110]}")
        return "\n".join(lines)


def summarise(lines: list[LogLine]) -> LogSummary:
    by_level: dict[str, int] = {}
    by_component: dict[str, int] = {}
    transitions: list[tuple[int, str, str]] = []
    reasons: list[int] = []
    statuses: list[int] = []

    for line in lines:
        by_level[line.level] = by_level.get(line.level, 0) + 1
        by_component[line.component] = by_component.get(line.component, 0) + 1

        if "state transition" in line.message:
            frm, to = line.fields.get("from"), line.fields.get("to")
            if frm and to:
                transitions.append((line.monotonic_ms, frm, to))

        r = line.get_int("reason")
        if r is not None:
            reasons.append(r)
        s = line.get_int("status")
        if s is not None and s != 0:
            statuses.append(s)

    return LogSummary(
        total=len(lines),
        by_level=by_level,
        by_component=by_component,
        errors=[line for line in lines if line.is_error],
        duration_ms=(lines[-1].monotonic_ms - lines[0].monotonic_ms) if lines else 0,
        state_transitions=transitions,
        final_state=transitions[-1][2] if transitions else None,
        reason_codes=reasons,
        status_codes=statuses,
    )


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="parse and summarise a wireless log")
    ap.add_argument("logfile")
    ap.add_argument("--errors-only", action="store_true")
    args = ap.parse_args()

    lines = parse_file(args.logfile)
    print(summarise(lines).describe())
    print()
    for line in lines:
        if args.errors_only and not line.is_error:
            continue
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
