"""Cross-validate our dissector against `tshark`.

The point of this module is a **test oracle**. Our parser in `dissect.py` and the
captures in `synth.py`/the C++ simulator were all written by the same person from
the same reading of the same spec — so they agree with each other by construction,
including wherever that reading is wrong. Three real bugs in this project
(BUILD_JOURNAL #5, #12, and a near-miss in #8) were found precisely because
`tshark` disagreed.

`tshark` is a decades-old independent implementation maintained by people who read
the standard more carefully than either of us. When it disagrees with us, the prior
should be that we are wrong.

`tshark` is optional. Where it is absent, the cross-check `skip`s with a stated
reason rather than passing silently — a check that quietly succeeds because its
oracle is missing is worse than no check, since it reports confidence it never
earned.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from airframe.pcap.dissect import Capture, FrameKind, load_capture

#: Map our frame kinds onto the 802.11 type/subtype values tshark reports, so the
#: two vocabularies can be compared. Several of our kinds are refinements tshark
#: expresses differently (SAE vs auth, EAPOL M1-M4), handled separately below.
SUBTYPE_OF: dict[FrameKind, int] = {
    FrameKind.ASSOC_REQUEST: 0x0000,
    FrameKind.ASSOC_RESPONSE: 0x0001,
    FrameKind.REASSOC_REQUEST: 0x0002,
    FrameKind.REASSOC_RESPONSE: 0x0003,
    FrameKind.PROBE_REQUEST: 0x0004,
    FrameKind.PROBE_RESPONSE: 0x0005,
    FrameKind.BEACON: 0x0008,
    FrameKind.DISASSOC: 0x000A,
    FrameKind.AUTH: 0x000B,
    FrameKind.SAE_COMMIT: 0x000B,
    FrameKind.SAE_CONFIRM: 0x000B,
    FrameKind.DEAUTH: 0x000C,
}


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


@dataclass
class Disagreement:
    frame: int
    field: str
    ours: object
    tshark: object

    def __str__(self) -> str:
        return f"frame #{self.frame} {self.field}: ours={self.ours!r} tshark={self.tshark!r}"


@dataclass
class CrossCheck:
    path: Path
    frame_count_ours: int
    frame_count_tshark: int
    disagreements: list[Disagreement] = field(default_factory=list)
    malformed_frames: list[int] = field(default_factory=list)
    skipped: str | None = None

    @property
    def agrees(self) -> bool:
        return (
            self.skipped is None
            and not self.disagreements
            and self.frame_count_ours == self.frame_count_tshark
        )

    def report(self) -> str:
        if self.skipped:
            return f"{self.path.name}: SKIPPED ({self.skipped})"
        lines = [
            f"{self.path.name}: {'AGREE' if self.agrees else 'DISAGREE'} "
            f"({self.frame_count_ours} frames ours / {self.frame_count_tshark} tshark)"
        ]
        if self.malformed_frames:
            lines.append(
                f"  tshark flags {len(self.malformed_frames)} malformed frame(s): "
                f"{self.malformed_frames[:10]}"
            )
        lines.extend(f"  {d}" for d in self.disagreements[:20])
        return "\n".join(lines)


def _tshark_fields(path: Path) -> list[dict[str, str]]:
    """Ask tshark for the fields we want to compare, one row per frame."""
    fields = [
        "frame.number",
        "wlan.fc.type_subtype",
        "wlan.fc.retry",
        "wlan.fixed.status_code",
        "wlan.fixed.reason_code",
        "wlan.ssid",
        "radiotap.dbm_antsignal",
        "eapol.type",
        "_ws.malformed",
    ]
    cmd = ["tshark", "-r", str(path), "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()[:300]}")

    rows: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        parts += [""] * (len(fields) - len(parts))
        # strict=False: parts was explicitly padded to len(fields) just above, but
        # tshark can emit an extra trailing field, and dropping it is correct.
        rows.append(dict(zip(fields, parts, strict=False)))
    return rows


def cross_check(cap: Capture) -> CrossCheck:
    """Compare our dissection of a capture against tshark's."""
    result = CrossCheck(path=cap.path, frame_count_ours=len(cap), frame_count_tshark=0)

    if not tshark_available():
        result.skipped = "tshark is not installed (brew install wireshark)"
        return result

    try:
        rows = _tshark_fields(cap.path)
    except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
        result.skipped = f"tshark could not read the capture: {exc}"
        return result

    result.frame_count_tshark = len(rows)

    for row in rows:
        try:
            number = int(row["frame.number"])
        except (ValueError, KeyError):
            continue
        if row.get("_ws.malformed"):
            result.malformed_frames.append(number)
        if number > len(cap.frames):
            continue
        ours = cap.frames[number - 1]

        # ---- type/subtype ----
        raw = row.get("wlan.fc.type_subtype", "")
        if raw:
            try:
                theirs = int(raw, 16) if raw.startswith("0x") else int(raw)
                expected = SUBTYPE_OF.get(ours.kind)
                if expected is not None and theirs != expected:
                    result.disagreements.append(
                        Disagreement(number, "type_subtype", hex(expected), hex(theirs))
                    )
            except ValueError:
                pass

        # ---- status / reason codes: exact integers, no interpretation involved ----
        for field_name, our_value in (
            ("wlan.fixed.status_code", ours.status_code),
            ("wlan.fixed.reason_code", ours.reason_code),
        ):
            raw_v = row.get(field_name, "")
            if not raw_v:
                continue
            try:
                theirs_v = int(raw_v, 16) if raw_v.startswith("0x") else int(raw_v)
            except ValueError:
                continue
            if our_value is not None and our_value != theirs_v:
                result.disagreements.append(
                    Disagreement(number, field_name.split(".")[-1], our_value, theirs_v)
                )

        # ---- SSID ----
        their_ssid = row.get("wlan.ssid", "")
        if their_ssid and ours.ssid and ours.ssid != "<hidden>":
            # tshark emits wlan.ssid as a HEX STRING, not as text: "airframe-test-ap"
            # comes back as "6169726672616d652d746573742d6170". Comparing it to our
            # decoded SSID reports a disagreement on every single beacon, which is
            # exactly the kind of false positive that trains people to ignore a
            # cross-check. Decode first, and fall back to the raw value only if it
            # is not valid hex.
            decoded = their_ssid
            try:
                decoded = bytes.fromhex(their_ssid).decode("utf-8", errors="replace")
            except ValueError:
                pass
            if decoded != ours.ssid:
                result.disagreements.append(
                    Disagreement(number, "ssid", ours.ssid, decoded)
                )

        # ---- retry flag ----
        their_retry = row.get("wlan.fc.retry", "")
        if their_retry in ("0", "1"):
            if ours.retry != bool(int(their_retry)):
                result.disagreements.append(
                    Disagreement(number, "retry", ours.retry, bool(int(their_retry)))
                )

        # ---- RSSI ----
        their_rssi = row.get("radiotap.dbm_antsignal", "")
        if their_rssi and ours.rssi_dbm is not None:
            try:
                # tshark can report a comma-separated list for multiple antennas.
                first = int(their_rssi.split(",")[0])
                if first != ours.rssi_dbm:
                    result.disagreements.append(
                        Disagreement(number, "rssi_dbm", ours.rssi_dbm, first)
                    )
            except ValueError:
                pass

        # ---- EAPOL presence ----
        their_eapol = bool(row.get("eapol.type", ""))
        if their_eapol != ours.is_eapol:
            result.disagreements.append(
                Disagreement(number, "is_eapol", ours.is_eapol, their_eapol)
            )

    return result


def cross_check_file(path: str | Path) -> CrossCheck:
    return cross_check(load_capture(path))


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="cross-validate our dissector against tshark")
    ap.add_argument("pcap", nargs="+")
    args = ap.parse_args()

    failures = 0
    for path in args.pcap:
        result = cross_check_file(path)
        print(result.report())
        if not result.agrees and not result.skipped:
            failures += 1
    print(f"\n{len(args.pcap) - failures}/{len(args.pcap)} captures agree with tshark")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_main())
