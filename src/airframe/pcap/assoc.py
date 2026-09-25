"""Connection forensics — reconstruct an association attempt from a raw capture.

This is the analysis a wireless engineer performs by hand, several times a day:
open the capture, walk the frames in order, work out how far the connection got,
and name the stage and reason it stopped. Automating it is the highest-leverage
thing in the whole packet layer, because it converts "here are 4,000 frames" into
one sentence a human can act on.

The output is a `Forensics` report naming:

* the **stage reached** (scan → auth → assoc → 4-way → data),
* **where it broke**, if it did,
* the **IEEE status or reason code** the AP gave,
* **per-stage timing**, so a slow connection can be attributed, and
* a **verdict** in plain language.

Deliberately rule-based, not machine-learned. The 802.11 association sequence is a
specified, finite state machine — the rules are *known*, so encoding them directly
produces an answer that is exact, explainable and auditable. Using ML for a
problem with a closed-form answer would be worse on every axis that matters, and
the ML layer later in the pipeline is applied where it genuinely earns its place
(clustering unknown failure shapes across many runs).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from airframe.pcap.dissect import Capture, FrameKind, load_capture

# IEEE 802.11 reason codes, for human-readable verdicts.
REASON_CODES: dict[int, str] = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving BSS",
    9: "STA requesting association is not authenticated",
    13: "Invalid element",
    14: "MIC failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "Element in 4-Way Handshake different from Beacon/Probe Response",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of the security policy",
    34: "Disassociated for poor channel conditions / beacon loss",
}

STATUS_CODES: dict[int, str] = {
    0: "Successful",
    1: "Unspecified failure",
    10: "Cannot support all requested capabilities",
    11: "Reassociation denied due to inability to confirm association exists",
    12: "Association denied for reason outside the scope of this standard",
    13: "Responding STA does not support the specified authentication algorithm",
    14: "Received an Authentication frame with an unexpected sequence number",
    15: "Authentication rejected because of challenge failure",
    16: "Authentication rejected due to timeout",
    17: "Association denied because AP is unable to handle additional STAs",
    18: "Association denied due to requesting STA not supporting all data rates",
    43: "Invalid AKMP",
    45: "Invalid RSN information element capabilities",
    53: "Invalid PMKID",
}


# Reason codes that mean "this was intentional", not "this broke".
#
# Codes 3 and 8 are the normal end of a session: a station deassociating because
# it is leaving. Treating them as failures makes every clean disconnect look like
# a bug -- which is exactly what the first version of this module did. See
# BUILD_JOURNAL.md #11.
GRACEFUL_REASONS: frozenset[int] = frozenset({3, 8})


class Stage(str, Enum):
    """How far the connection got. Ordered, so comparisons are meaningful."""

    NOTHING = "nothing"
    SCANNED = "scanned"
    AUTHENTICATED = "authenticated"
    ASSOCIATED = "associated"
    KEYED = "keyed"
    DATA = "data"

    @property
    def rank(self) -> int:
        return list(Stage).index(self)


@dataclass
class StageTiming:
    name: str
    start_s: float
    end_s: float

    @property
    def duration_ms(self) -> int:
        return int((self.end_s - self.start_s) * 1000)


@dataclass
class Forensics:
    """The verdict on one capture."""

    path: Path
    total_frames: int
    duration_s: float
    stage_reached: Stage = Stage.NOTHING
    succeeded: bool = False
    failed_at: Stage | None = None
    status_code: int | None = None
    reason_code: int | None = None
    verdict: str = ""
    evidence: list[str] = field(default_factory=list)
    timings: list[StageTiming] = field(default_factory=list)
    ssid: str | None = None
    bssid: str | None = None
    akm: str | None = None
    eapol_seen: list[str] = field(default_factory=list)
    retry_rate: float = 0.0
    rssi_first: int | None = None
    rssi_last: int | None = None

    def timing(self, name: str) -> int | None:
        for t in self.timings:
            if t.name == name:
                return t.duration_ms
        return None

    @property
    def slowest_stage(self) -> StageTiming | None:
        return max(self.timings, key=lambda t: t.duration_ms) if self.timings else None

    def report(self) -> str:
        """Multi-line human-readable report — the thing you paste into a bug."""
        lines = [
            f"Capture      : {self.path.name}",
            f"Frames       : {self.total_frames} over {self.duration_s:.3f}s",
            f"Network      : {self.ssid or '<unknown>'} ({self.bssid or '<unknown>'})"
            + (f" AKM={self.akm}" if self.akm else ""),
            f"Stage reached: {self.stage_reached.value}",
            f"Outcome      : {'SUCCESS' if self.succeeded else 'FAILURE'}",
        ]
        if not self.succeeded and self.failed_at:
            lines.append(f"Failed at    : {self.failed_at.value}")
        if self.reason_code is not None:
            lines.append(
                f"Reason code  : {self.reason_code} "
                f"({REASON_CODES.get(self.reason_code, 'unknown')})"
            )
        if self.status_code is not None and self.status_code != 0:
            lines.append(
                f"Status code  : {self.status_code} "
                f"({STATUS_CODES.get(self.status_code, 'unknown')})"
            )
        lines.append(f"VERDICT      : {self.verdict}")

        if self.timings:
            lines.append("\nStage timings:")
            for t in self.timings:
                marker = "  <-- slowest" if t is self.slowest_stage and len(self.timings) > 1 else ""
                lines.append(f"  {t.name:<22} {t.duration_ms:>7} ms{marker}")

        if self.eapol_seen:
            lines.append(f"\nEAPOL messages: {' '.join(self.eapol_seen)}")
        lines.append(f"Retry rate    : {self.retry_rate:.1%}")
        if self.rssi_first is not None:
            lines.append(f"RSSI          : {self.rssi_first} -> {self.rssi_last} dBm")

        if self.evidence:
            lines.append("\nEvidence:")
            lines.extend(f"  - {e}" for e in self.evidence)
        return "\n".join(lines)


# ---------------------------------------------------------------- the analysis


def _stage_timings(cap: Capture) -> list[StageTiming]:
    """Time each stage from the frames that bracket it."""
    out: list[StageTiming] = []

    def first_time(*kinds: FrameKind) -> float | None:
        f = cap.first(*kinds)
        return f.time_s if f else None

    def last_time(*kinds: FrameKind) -> float | None:
        matches = cap.of_kind(*kinds)
        return matches[-1].time_s if matches else None

    probe = first_time(FrameKind.PROBE_REQUEST)
    beacon_or_resp = first_time(FrameKind.PROBE_RESPONSE, FrameKind.BEACON)
    auth_start = first_time(FrameKind.AUTH, FrameKind.SAE_COMMIT)
    auth_end = last_time(FrameKind.AUTH, FrameKind.SAE_CONFIRM)
    assoc_req = first_time(FrameKind.ASSOC_REQUEST, FrameKind.REASSOC_REQUEST)
    assoc_resp = first_time(FrameKind.ASSOC_RESPONSE, FrameKind.REASSOC_RESPONSE)
    m1 = first_time(FrameKind.EAPOL_M1)
    m4 = last_time(FrameKind.EAPOL_M4)
    last_eapol = last_time(
        FrameKind.EAPOL_M1, FrameKind.EAPOL_M2, FrameKind.EAPOL_M3, FrameKind.EAPOL_M4
    )

    if probe is not None and beacon_or_resp is not None and beacon_or_resp >= probe:
        out.append(StageTiming("scan", probe, beacon_or_resp))
    if auth_start is not None and auth_end is not None and auth_end >= auth_start:
        out.append(StageTiming("authentication", auth_start, auth_end))
    if assoc_req is not None and assoc_resp is not None and assoc_resp >= assoc_req:
        out.append(StageTiming("association", assoc_req, assoc_resp))
    if m1 is not None:
        end = m4 if m4 is not None else last_eapol
        if end is not None and end >= m1:
            out.append(StageTiming("4-way handshake", m1, end))
    # The gap between authentication starting and the first frame: on a real
    # capture this is dominated by the scan dwell time.
    if probe is not None and auth_start is not None and auth_start >= probe:
        out.append(StageTiming("scan->auth latency", probe, auth_start))
    return out


def analyse(cap: Capture) -> Forensics:
    """Reconstruct the association attempt and reach a verdict."""
    report = Forensics(
        path=cap.path,
        total_frames=len(cap),
        duration_s=cap.duration_s,
        retry_rate=cap.retry_rate,
        timings=_stage_timings(cap),
    )

    trend = cap.rssi_trend()
    if trend:
        report.rssi_first, report.rssi_last = trend

    # ---- identify the network ----
    for f in cap:
        if f.ssid and f.ssid not in ("<hidden>", ""):
            report.ssid = f.ssid
            break
    for f in cap:
        if f.rsn_akm:
            report.akm = f.rsn_akm
            break
    bssids = [b for b in cap.bssids() if b != "ff:ff:ff:ff:ff:ff"]
    report.bssid = bssids[0] if bssids else None

    # ---- how far did it get? ----
    has_scan = bool(cap.of_kind(FrameKind.BEACON, FrameKind.PROBE_RESPONSE))
    auth_frames = cap.of_kind(FrameKind.AUTH, FrameKind.SAE_COMMIT, FrameKind.SAE_CONFIRM)
    assoc_resp = cap.of_kind(FrameKind.ASSOC_RESPONSE, FrameKind.REASSOC_RESPONSE)
    m1 = cap.of_kind(FrameKind.EAPOL_M1)
    m2 = cap.of_kind(FrameKind.EAPOL_M2)
    m3 = cap.of_kind(FrameKind.EAPOL_M3)
    m4 = cap.of_kind(FrameKind.EAPOL_M4)
    data = [f for f in cap if f.ftype == 2 and not f.is_eapol]
    deauths = cap.of_kind(FrameKind.DEAUTH, FrameKind.DISASSOC)

    for name, frames in (("M1", m1), ("M2", m2), ("M3", m3), ("M4", m4)):
        if frames:
            report.eapol_seen.append(f"{name}x{len(frames)}" if len(frames) > 1 else name)

    if has_scan:
        report.stage_reached = Stage.SCANNED
    if auth_frames:
        # Authentication "succeeded" only if some auth frame carried status 0 AND
        # we progressed. A rejected auth is still an auth frame.
        if any(f.status_code == 0 for f in auth_frames):
            report.stage_reached = Stage.AUTHENTICATED
    if assoc_resp:
        ok_assoc = [f for f in assoc_resp if f.status_code == 0]
        if ok_assoc:
            report.stage_reached = Stage.ASSOCIATED
        else:
            report.status_code = assoc_resp[-1].status_code
    if m3 and m4:
        report.stage_reached = Stage.KEYED
    if data:
        report.stage_reached = Stage.DATA

    # ---- the deauth/disassoc reason, if any ----
    if deauths:
        report.reason_code = deauths[-1].reason_code

    # ---- verdict, most specific rule first ----
    #
    # Order matters: every branch below is reachable, and a looser rule placed
    # earlier would swallow a more precise diagnosis.

    if not cap.frames:
        report.verdict = "capture is empty — nothing was recorded"
        report.failed_at = Stage.NOTHING
        return report

    if not has_scan:
        report.verdict = (
            "no beacons or probe responses: the AP was never heard. "
            "Either it is off, out of range, or on a channel we did not capture"
        )
        report.failed_at = Stage.NOTHING
        report.evidence.append(f"{len(cap)} frames captured, none from an AP")
        return report

    if not auth_frames:
        report.verdict = (
            "the AP was visible but the station never attempted authentication"
        )
        report.failed_at = Stage.SCANNED
        return report

    # Authentication rejected outright
    bad_auth = [f for f in auth_frames if f.status_code not in (0, None)]
    if bad_auth and not assoc_resp:
        code = bad_auth[-1].status_code
        report.status_code = code
        report.failed_at = Stage.SCANNED
        report.verdict = (
            f"authentication rejected with status {code} "
            f"({STATUS_CODES.get(code or -1, 'unknown')})"
        )
        return report

    # Authentication started but got no reply
    if not assoc_resp and not cap.of_kind(FrameKind.ASSOC_REQUEST):
        n_auth = len(auth_frames)
        report.failed_at = Stage.SCANNED
        report.verdict = (
            f"authentication timed out: {n_auth} auth frame(s) sent, no association "
            "was ever attempted. The AP stopped responding after the auth request"
        )
        report.evidence.append(f"auth frames: {n_auth}, assoc responses: 0")
        return report

    # Association rejected
    if assoc_resp and all(f.status_code != 0 for f in assoc_resp):
        code = assoc_resp[-1].status_code
        report.status_code = code
        report.failed_at = Stage.AUTHENTICATED
        report.verdict = (
            f"association rejected by the AP with status {code} "
            f"({STATUS_CODES.get(code or -1, 'unknown')})"
        )
        report.evidence.append(f"assoc response status={code}")
        return report

    # ---- 4-way handshake analysis: the richest source of real failures ----
    if report.stage_reached is Stage.ASSOCIATED and (m1 or m2):
        if m1 and not m2:
            report.failed_at = Stage.ASSOCIATED
            report.verdict = (
                "4-way handshake stalled at M1: the AP sent M1 but the station "
                "never replied with M2. Suspect the supplicant or a driver problem "
                "on the client side"
            )
        elif m2 and not m3:
            # The signature case. Distinguish a timeout from a rejection using the
            # deauth reason code -- same stage, completely different owner.
            retries = len(m2)
            report.failed_at = Stage.ASSOCIATED
            if report.reason_code == 23:
                report.verdict = (
                    "4-way handshake failed authentication: the AP rejected the "
                    "station's MIC (reason 23, 802.1X failure). This is almost "
                    "always a wrong passphrase / PMK mismatch, not a network fault"
                )
            elif report.reason_code == 15:
                report.verdict = (
                    f"4-way handshake timed out waiting for M3: the station sent M2 "
                    f"{retries} time(s) and the AP never answered (reason 15). "
                    "The AP or its authenticator is at fault, not the client"
                )
            else:
                report.verdict = (
                    f"4-way handshake incomplete: M2 sent {retries} time(s), M3 "
                    "never arrived, and no deauth reason was recorded"
                )
            report.evidence.append(f"EAPOL M2 transmitted {retries} time(s)")
            report.evidence.append("M3 never observed")
            if report.reason_code is not None:
                report.evidence.append(
                    f"deauth reason {report.reason_code}: "
                    f"{REASON_CODES.get(report.reason_code, 'unknown')}"
                )
            return report
        elif m3 and not m4:
            report.failed_at = Stage.ASSOCIATED
            report.verdict = (
                "4-way handshake stalled at M3: the AP sent M3 but the station "
                "never confirmed with M4. Suspect key installation on the client"
            )
        return report

    # Associated, keyed, then dropped.
    #
    # First decide whether the teardown was intentional. A station that completed
    # the handshake and then sent its own deauth with reason 3/8 did exactly what it
    # was told to do; that is a successful session, not a failure.
    graceful = False
    if deauths:
        last = deauths[-1]
        code = last.reason_code
        if code in GRACEFUL_REASONS:
            sta_initiated = bool(
                report.bssid and last.addr2 and last.addr2.lower() != report.bssid.lower()
            )
            # STA-initiated is unambiguous. An AP-sent reason 3 is also routine
            # (the AP is deassociating us deliberately, e.g. on a config change)
            # provided the session had already reached a keyed state.
            graceful = sta_initiated or report.stage_reached in (Stage.KEYED, Stage.DATA)

    if report.stage_reached in (Stage.KEYED, Stage.DATA) and deauths and graceful:
        report.succeeded = True
        report.reason_code = deauths[-1].reason_code
        report.verdict = (
            "connection completed successfully and was then closed cleanly "
            f"(reason {report.reason_code}: "
            f"{REASON_CODES.get(report.reason_code or -1, 'unknown')})"
        )
        if report.retry_rate > 0.20:
            report.verdict += (
                f" — however the retry rate of {report.retry_rate:.1%} indicates "
                "significant channel contention while connected"
            )
            report.evidence.append(
                f"retry rate {report.retry_rate:.1%} exceeds the 20% threshold"
            )
        if report.rssi_last is not None and report.rssi_last < -80:
            report.evidence.append(
                f"signal was weak throughout: RSSI ended at {report.rssi_last} dBm"
            )
        return report

    if report.stage_reached in (Stage.KEYED, Stage.DATA) and deauths:
        code = report.reason_code
        report.failed_at = report.stage_reached
        if code == 34:
            report.verdict = (
                "link established, then lost to beacon loss (reason 34): the "
                "station stopped hearing the AP. Check range, interference or an AP reset"
            )
            if report.rssi_last is not None and report.rssi_last < -80:
                report.evidence.append(
                    f"RSSI had fallen to {report.rssi_last} dBm before the drop"
                )  # noqa: SIM102
        else:
            report.verdict = (
                f"link established, then torn down with reason {code} "
                f"({REASON_CODES.get(code or -1, 'unknown')})"
            )
        report.evidence.append(f"reached {report.stage_reached.value} before dropping")
        return report

    # Success paths
    if report.stage_reached is Stage.DATA:
        report.succeeded = True
        report.verdict = "connection completed successfully and passed data"
        if report.retry_rate > 0.20:
            report.verdict += (
                f" — but the retry rate of {report.retry_rate:.1%} indicates "
                "significant channel contention"
            )
            report.evidence.append(f"retry rate {report.retry_rate:.1%} exceeds the 20% threshold")
        return report

    if report.stage_reached is Stage.KEYED:
        report.succeeded = True
        report.verdict = (
            "association and 4-way handshake completed; no data frames were "
            "captured afterwards (the capture may simply have ended, or DHCP "
            "may have failed — check the logs, not the radio)"
        )
        return report

    if report.stage_reached is Stage.ASSOCIATED:
        report.succeeded = True
        report.verdict = (
            "associated on an open network (no 4-way handshake expected)"
            if report.akm is None
            else "associated, but the expected 4-way handshake never started"
        )
        if report.akm is not None:
            report.succeeded = False
            report.failed_at = Stage.ASSOCIATED
        return report

    report.verdict = f"reached {report.stage_reached.value}; no further diagnosis available"
    return report


def analyse_file(path: str | Path) -> Forensics:
    return analyse(load_capture(path))


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="reconstruct an 802.11 association from a capture")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--brief", action="store_true", help="one line per capture")
    args = ap.parse_args()

    for path in args.pcap:
        report = analyse_file(path)
        if args.brief:
            mark = "OK  " if report.succeeded else "FAIL"
            print(f"{mark} {Path(path).name:<34} {report.verdict[:96]}")
        else:
            print(report.report())
            print("\n" + "=" * 78 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
