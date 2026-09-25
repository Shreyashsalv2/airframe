"""Rule-based anomaly detectors over a dissected capture.

These are the patterns a wireless engineer scans for by eye. Separated from
`assoc.py` because they answer a different question: `assoc.py` asks "did this one
connection attempt succeed", while these ask "is anything in this capture
suspicious", including on captures where the connection worked fine.

Every detector returns a severity and an explanation. Thresholds are named
constants with the reasoning recorded next to them — an unexplained magic number in
a detector is a future argument nobody can settle.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum

from airframe.pcap.dissect import Capture, FrameKind

# ---------------------------------------------------------------- thresholds

#: Above this, contention is degrading throughput noticeably. A healthy link sits
#: at 1-5%; 20% is where users start describing the network as "slow".
RETRY_RATE_WARN = 0.20
RETRY_RATE_CRITICAL = 0.40

#: 802.11 rate adaptation collapses below roughly 15 dB SNR; -80 dBm with a
#: typical -95 dBm noise floor is the practical edge of usability.
RSSI_WEAK_DBM = -80
RSSI_CRITICAL_DBM = -88

#: More than this many deauths in a capture is not normal churn. Deauth floods are
#: also the classic denial-of-service against unprotected networks, which is why
#: WPA3 mandates Management Frame Protection.
DEAUTH_FLOOD_COUNT = 5

#: A station changing BSSID more than this in one capture is thrashing rather than
#: roaming: each transition costs real user-visible disruption.
ROAM_CHURN_COUNT = 3

#: Retransmitting one EAPOL message this many times means the peer is not answering.
EAPOL_RETRY_WARN = 2


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Anomaly:
    detector: str
    severity: Severity
    summary: str
    detail: str = ""
    value: float | None = None

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.detector}: {self.summary}"


# ---------------------------------------------------------------- detectors


def detect_excessive_retries(cap: Capture) -> list[Anomaly]:
    rate = cap.retry_rate
    data_frames = sum(1 for f in cap if f.ftype == 2)
    if data_frames < 10:
        return []          # too small a sample to say anything
    if rate >= RETRY_RATE_CRITICAL:
        sev = Severity.CRITICAL
    elif rate >= RETRY_RATE_WARN:
        sev = Severity.WARNING
    else:
        return []
    return [
        Anomaly(
            "excessive_retries",
            sev,
            f"{rate:.1%} of data frames are retransmissions",
            f"{sum(1 for f in cap if f.ftype == 2 and f.retry)} of {data_frames} data frames "
            f"carry the retry bit (threshold {RETRY_RATE_WARN:.0%}). "
            "Indicates channel contention, interference, or a marginal link.",
            rate,
        )
    ]


def detect_weak_signal(cap: Capture) -> list[Anomaly]:
    values = cap.rssi_values
    if not values:
        return []
    worst = min(values)
    mean = sum(values) / len(values)
    if worst > RSSI_WEAK_DBM:
        return []
    sev = Severity.CRITICAL if worst <= RSSI_CRITICAL_DBM else Severity.WARNING
    return [
        Anomaly(
            "weak_signal",
            sev,
            f"signal reached {worst} dBm (mean {mean:.1f} dBm)",
            f"Below {RSSI_WEAK_DBM} dBm, 802.11 rate adaptation drops to the lowest MCS "
            "and retries climb. Check distance, obstructions and AP transmit power.",
            float(worst),
        )
    ]


def detect_rssi_collapse(cap: Capture) -> list[Anomaly]:
    """A signal falling away sharply before a disconnect — the fingerprint of the
    client walking out of range, as opposed to the AP failing."""
    values = cap.rssi_values
    if len(values) < 8:
        return []
    head = values[: len(values) // 3]
    tail = values[-len(values) // 3 :]
    drop = (sum(head) / len(head)) - (sum(tail) / len(tail))
    if drop < 12:
        return []
    disconnected = bool(cap.of_kind(FrameKind.DEAUTH, FrameKind.DISASSOC))
    return [
        Anomaly(
            "rssi_collapse",
            Severity.WARNING if not disconnected else Severity.CRITICAL,
            f"signal fell {drop:.0f} dB over the capture",
            f"Started around {sum(head) / len(head):.0f} dBm, ended around "
            f"{sum(tail) / len(tail):.0f} dBm"
            + (", followed by a disconnect" if disconnected else "")
            + ". Consistent with the station moving out of range rather than an AP fault.",
            drop,
        )
    ]


def detect_deauth_flood(cap: Capture) -> list[Anomaly]:
    deauths = cap.of_kind(FrameKind.DEAUTH, FrameKind.DISASSOC)
    if len(deauths) < DEAUTH_FLOOD_COUNT:
        return []
    reasons = Counter(f.reason_code for f in deauths if f.reason_code is not None)
    window = deauths[-1].time_s - deauths[0].time_s
    return [
        Anomaly(
            "deauth_flood",
            Severity.CRITICAL,
            f"{len(deauths)} deauth/disassoc frames in {window:.2f}s",
            f"Reason codes: {dict(reasons)}. A burst of deauths is either a badly "
            "misbehaving AP or a deauth-flood denial of service. Note that WPA3's "
            "mandatory Management Frame Protection exists specifically to prevent "
            "the spoofed-deauth attack.",
            float(len(deauths)),
        )
    ]


def detect_eapol_retransmissions(cap: Capture) -> list[Anomaly]:
    out: list[Anomaly] = []
    for kind, label in (
        (FrameKind.EAPOL_M1, "M1"),
        (FrameKind.EAPOL_M2, "M2"),
        (FrameKind.EAPOL_M3, "M3"),
        (FrameKind.EAPOL_M4, "M4"),
    ):
        frames = cap.of_kind(kind)
        if len(frames) > EAPOL_RETRY_WARN:
            # Which side is retrying tells you which side is waiting, and therefore
            # which side is not answering. That is the actionable part.
            waiting_for = {"M1": "M2", "M2": "M3", "M3": "M4", "M4": "confirmation"}[label]
            blame = {"M1": "the station", "M2": "the AP", "M3": "the station",
                     "M4": "the AP"}[label]
            out.append(
                Anomaly(
                    "eapol_retransmission",
                    Severity.CRITICAL,
                    f"EAPOL {label} retransmitted {len(frames)} times",
                    f"The sender kept retrying {label} because {waiting_for} never "
                    f"arrived, so {blame} stopped responding during the 4-way handshake.",
                    float(len(frames)),
                )
            )
    return out


def detect_incomplete_handshake(cap: Capture) -> list[Anomaly]:
    m = {
        k: len(cap.of_kind(k))
        for k in (FrameKind.EAPOL_M1, FrameKind.EAPOL_M2, FrameKind.EAPOL_M3, FrameKind.EAPOL_M4)
    }
    started = m[FrameKind.EAPOL_M1] or m[FrameKind.EAPOL_M2]
    if not started:
        return []
    if m[FrameKind.EAPOL_M3] and m[FrameKind.EAPOL_M4]:
        return []
    missing = [
        label
        for label, key in (
            ("M1", FrameKind.EAPOL_M1), ("M2", FrameKind.EAPOL_M2),
            ("M3", FrameKind.EAPOL_M3), ("M4", FrameKind.EAPOL_M4),
        )
        if not m[key]
    ]
    return [
        Anomaly(
            "incomplete_handshake",
            Severity.CRITICAL,
            f"4-way handshake incomplete: missing {', '.join(missing)}",
            "Without all four messages no pairwise key is installed, so the link "
            "cannot carry encrypted data even if association succeeded.",
        )
    ]


def detect_roam_churn(cap: Capture) -> list[Anomaly]:
    """BSSID changes over time — distinguishes roaming from thrashing."""
    sequence: list[str] = []
    for f in cap:
        if f.kind in (FrameKind.ASSOC_REQUEST, FrameKind.REASSOC_REQUEST) and f.addr1:
            if not sequence or sequence[-1] != f.addr1:
                sequence.append(f.addr1)
    transitions = max(len(sequence) - 1, 0)
    if transitions < ROAM_CHURN_COUNT:
        return []
    # Revisiting a BSSID is the specific signature of ping-pong, as opposed to a
    # station legitimately walking past several APs.
    pingpong = len(set(sequence)) < len(sequence)
    return [
        Anomaly(
            "roam_churn",
            Severity.CRITICAL if pingpong else Severity.WARNING,
            f"{transitions} BSS transitions in {cap.duration_s:.2f}s"
            + (" (ping-pong: BSSIDs repeat)" if pingpong else ""),
            f"Sequence: {' -> '.join(sequence)}. Each transition interrupts user "
            "traffic. Repeated returns to a previous BSSID indicate roaming "
            "thresholds that are too close together, not genuine mobility.",
            float(transitions),
        )
    ]


def detect_bad_fcs(cap: Capture) -> list[Anomaly]:
    bad = [f for f in cap if f.bad_fcs]
    if not bad:
        return []
    rate = len(bad) / len(cap)
    if rate < 0.05:
        return []
    return [
        Anomaly(
            "bad_fcs",
            Severity.WARNING if rate < 0.20 else Severity.CRITICAL,
            f"{rate:.1%} of frames failed the frame check sequence",
            f"{len(bad)} of {len(cap)} frames are corrupt. Indicates interference or "
            "a capture problem — note that a high bad-FCS rate can also just mean the "
            "capturing radio is at the edge of range, so rule that out first.",
            rate,
        )
    ]


def detect_unprotected_management(cap: Capture) -> list[Anomaly]:
    """WPA3 requires Management Frame Protection; note when a deauth is unprotected.

    Informational rather than a defect: it explains *why* a network is vulnerable
    to spoofed deauth, which is the single most common Wi-Fi attack.
    """
    akm = next((f.rsn_akm for f in cap if f.rsn_akm), None)
    deauths = cap.of_kind(FrameKind.DEAUTH, FrameKind.DISASSOC)
    if not deauths or akm in (None, "SAE", "FT-SAE", "OWE"):
        return []
    unprotected = [f for f in deauths if not f.protected]
    if not unprotected:
        return []
    return [
        Anomaly(
            "unprotected_management_frames",
            Severity.INFO,
            f"{len(unprotected)} unprotected deauth/disassoc frame(s) on a {akm} network",
            "Without Management Frame Protection these frames can be spoofed by any "
            "nearby device, which is the basis of the deauth denial-of-service attack. "
            "WPA3-SAE mandates MFP and is not susceptible.",
        )
    ]


def detect_key_reinstallation(cap: Capture) -> list[Anomaly]:
    """KRACK-style key reinstallation: EAPOL M3 replayed after the handshake completed.

    CVE-2017-13077 and relatives. Replaying handshake message 3 makes a vulnerable
    client reinstall the pairwise key, which resets its nonce/packet-number counter
    and permits keystream reuse — the attacker can then decrypt or forge traffic.

    The observable signature needs no decryption at all:
      * the handshake already completed (M3 and M4 both seen), AND
      * further M3 frames arrive afterwards, AND
      * their replay counters increase (a genuine retransmission reuses its counter;
        an attacker replaying must increment it to be accepted).

    That last clause is what separates this from an ordinary retransmission, and it
    is why this detector is worth having rather than folding into
    `detect_eapol_retransmissions`.
    """
    m3 = cap.of_kind(FrameKind.EAPOL_M3)
    m4 = cap.of_kind(FrameKind.EAPOL_M4)
    if len(m3) < 2 or not m4:
        return []

    first_m4 = m4[0].time_s
    after = [f for f in m3 if f.time_s >= first_m4]
    if not after:
        return []

    counters = [f.replay_counter for f in m3 if f.replay_counter is not None]
    increasing = len(set(counters)) > 1 and counters == sorted(counters)

    return [
        Anomaly(
            "key_reinstallation",
            Severity.CRITICAL,
            f"EAPOL M3 replayed {len(after)} time(s) after the handshake completed",
            f"Replay counters observed: {counters}."
            + (
                " They increase, which is the KRACK signature — a genuine "
                "retransmission reuses its counter, so an increasing sequence after "
                "M4 indicates deliberate replay aimed at forcing key reinstallation."
                if increasing
                else " Counters do not increase, so this may be benign retransmission."
            ),
            float(len(after)),
        )
    ]


ALL_DETECTORS = (
    detect_excessive_retries,
    detect_weak_signal,
    detect_rssi_collapse,
    detect_deauth_flood,
    detect_eapol_retransmissions,
    detect_key_reinstallation,
    detect_incomplete_handshake,
    detect_roam_churn,
    detect_bad_fcs,
    detect_unprotected_management,
)


def scan_capture(cap: Capture) -> list[Anomaly]:
    """Run every detector, most severe first."""
    found: list[Anomaly] = []
    for detector in ALL_DETECTORS:
        try:
            found.extend(detector(cap))
        except (IndexError, ValueError, TypeError, ZeroDivisionError):
            # One broken detector must not blind the other eight.
            continue
    order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    return sorted(found, key=lambda a: order[a.severity])


def _main() -> int:
    import argparse

    from airframe.pcap.dissect import load_capture

    ap = argparse.ArgumentParser(description="scan an 802.11 capture for anomalies")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    for path in args.pcap:
        cap = load_capture(path)
        found = scan_capture(cap)
        print(f"\n{cap.path.name}  ({len(cap)} frames)")
        if not found:
            print("  no anomalies detected")
            continue
        for a in found:
            print(f"  {a}")
            if args.verbose and a.detail:
                print(f"      {a.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
