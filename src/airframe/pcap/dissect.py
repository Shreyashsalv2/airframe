"""802.11 frame dissection — turning a raw capture into structured facts.

Uses Scapy for the binary parsing, but deliberately keeps its own domain model on
top. Scapy gives you `Dot11`, `Dot11Beacon`, `EAPOL` objects; what an engineer
actually needs is "which stage of the connection was this, and did it succeed".
That translation is the value here.

A note on Scapy and RadioTap, because it costs people hours: Scapy's RadioTap
field names vary across versions, and several fields are only present when the
corresponding `present` bit is set. Reading `pkt[RadioTap].dBm_AntSignal`
unconditionally works on your machine and raises `AttributeError` on someone
else's. Every radio-metadata read here goes through `_radiotap_field`, which
probes several spellings and returns None rather than raising.
"""

from __future__ import annotations

import warnings
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# Scapy is noisy on import and emits cryptography deprecation warnings that have
# nothing to do with us. Suppressed narrowly, not globally.
# Scapy pulls in a TLS module that emits CryptographyDeprecationWarning at import
# time. It is unrelated to anything here, and it pollutes every CLI invocation, so
# it is filtered by message rather than by category (the class lives inside
# `cryptography` and importing it just to name it would be worse).
warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy.*")
warnings.filterwarnings("ignore", message=r".*(cryptography|Diffie-Hellman|FFDH).*")
warnings.filterwarnings("ignore", message=r".*TripleDES.*")

from scapy.all import RadioTap, rdpcap  # noqa: E402
from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ReassoResp,
)
from scapy.layers.eap import EAPOL  # noqa: E402


class FrameKind(str, Enum):
    """What a frame means in connection terms, not what its subtype number is."""

    BEACON = "beacon"
    PROBE_REQUEST = "probe_request"
    PROBE_RESPONSE = "probe_response"
    AUTH = "auth"
    SAE_COMMIT = "sae_commit"
    SAE_CONFIRM = "sae_confirm"
    ASSOC_REQUEST = "assoc_request"
    ASSOC_RESPONSE = "assoc_response"
    REASSOC_REQUEST = "reassoc_request"
    REASSOC_RESPONSE = "reassoc_response"
    DEAUTH = "deauth"
    DISASSOC = "disassoc"
    EAPOL_M1 = "eapol_m1"
    EAPOL_M2 = "eapol_m2"
    EAPOL_M3 = "eapol_m3"
    EAPOL_M4 = "eapol_m4"
    EAPOL_UNKNOWN = "eapol_unknown"
    DATA = "data"
    QOS_DATA = "qos_data"
    CONTROL = "control"
    OTHER = "other"


# IEEE 802.11 auth algorithms
AUTH_ALGO_OPEN = 0
AUTH_ALGO_SAE = 3

# The four EAPOL-Key messages, identified by their Key Information bits.
# This is precisely how Wireshark labels them, and getting it wrong is the
# difference between a readable capture and an unreadable one.
_KEY_MIC = 1 << 8
_KEY_ACK = 1 << 7
_KEY_INSTALL = 1 << 6
_KEY_SECURE = 1 << 9
_KEY_ENCRYPTED = 1 << 12


@dataclass
class Frame:
    """One dissected 802.11 frame."""

    index: int
    time_s: float
    kind: FrameKind
    subtype: int
    ftype: int
    addr1: str | None = None
    addr2: str | None = None
    addr3: str | None = None
    seq: int | None = None
    retry: bool = False
    protected: bool = False
    length: int = 0

    # radio metadata (None when the capture did not carry it)
    rssi_dbm: int | None = None
    freq_mhz: int | None = None
    rate_mbps: float | None = None
    bad_fcs: bool = False

    # protocol payload facts
    ssid: str | None = None
    status_code: int | None = None
    reason_code: int | None = None
    auth_algo: int | None = None
    auth_seq: int | None = None
    aid: int | None = None
    key_info: int | None = None
    replay_counter: int | None = None
    rsn_akm: str | None = None
    elements: list[int] = field(default_factory=list)

    @property
    def is_management(self) -> bool:
        return self.ftype == 0

    @property
    def is_eapol(self) -> bool:
        return self.kind.value.startswith("eapol")

    def summary(self) -> str:
        bits = [f"#{self.index:<4} {self.time_s:8.3f}s {self.kind.value:<16}"]
        if self.ssid:
            bits.append(f'ssid="{self.ssid}"')
        if self.status_code is not None:
            bits.append(f"status={self.status_code}")
        if self.reason_code is not None:
            bits.append(f"reason={self.reason_code}")
        if self.rssi_dbm is not None:
            bits.append(f"rssi={self.rssi_dbm}")
        if self.retry:
            bits.append("RETRY")
        return " ".join(bits)


# ---------------------------------------------------------------- radiotap


def _radiotap_field(pkt: Any, *names: str) -> Any:
    """Read a RadioTap field, tolerating Scapy version differences.

    Scapy renamed several of these between versions and omits fields whose
    `present` bit is clear. Probing candidate spellings and returning None is the
    only portable approach; a direct attribute read is a latent crash.
    """
    if not pkt.haslayer(RadioTap):
        return None
    rt = pkt[RadioTap]
    for name in names:
        try:
            value = getattr(rt, name, None)
        except (AttributeError, IndexError, ValueError, TypeError):
            continue
        if value is not None:
            # Some Scapy versions return a list for multi-antenna fields.
            if isinstance(value, (list, tuple)):
                return value[0] if value else None
            return value
    return None


def _has_bad_fcs(pkt: Any) -> bool:
    flags = _radiotap_field(pkt, "Flags", "flags")
    if flags is None:
        return False
    try:
        return bool(int(flags) & 0x40)
    except (TypeError, ValueError):
        # Newer Scapy exposes Flags as a FlagValue object rather than an int.
        return "FCSerror" in str(flags) or "badFCS" in str(flags)


# ---------------------------------------------------------------- classification


def _classify_eapol(pkt: Any) -> tuple[FrameKind, int | None, int | None]:
    """Identify which of M1..M4 an EAPOL-Key frame is, from its Key Info bits.

    The logic mirrors the spec:
      M1: ACK, no MIC            (the STA has no PTK yet, so it cannot verify one)
      M2: MIC, not Secure
      M3: MIC + ACK + Install/Secure
      M4: MIC + Secure, no ACK
    """
    try:
        eapol = pkt[EAPOL]
        raw = bytes(eapol.payload) if eapol.payload else b""
        if len(raw) < 3 or eapol.type != 3:
            return FrameKind.EAPOL_UNKNOWN, None, None
        key_info = int.from_bytes(raw[1:3], "big")
        replay = int.from_bytes(raw[5:13], "big") if len(raw) >= 13 else None

        mic = bool(key_info & _KEY_MIC)
        ack = bool(key_info & _KEY_ACK)
        secure = bool(key_info & _KEY_SECURE)
        install = bool(key_info & _KEY_INSTALL)

        if not mic and ack:
            return FrameKind.EAPOL_M1, key_info, replay
        if mic and ack and (install or secure):
            return FrameKind.EAPOL_M3, key_info, replay
        if mic and secure and not ack:
            return FrameKind.EAPOL_M4, key_info, replay
        if mic and not secure:
            return FrameKind.EAPOL_M2, key_info, replay
        return FrameKind.EAPOL_UNKNOWN, key_info, replay
    except (IndexError, AttributeError, ValueError):
        return FrameKind.EAPOL_UNKNOWN, None, None


def _extract_elements(pkt: Any) -> tuple[list[int], str | None, str | None]:
    """Walk the Information Element chain. Returns (ids, ssid, akm-name)."""
    ids: list[int] = []
    ssid: str | None = None
    akm: str | None = None

    elt = pkt.getlayer(Dot11Elt)
    guard = 0
    while elt is not None and guard < 64:      # guard against a malformed IE loop
        guard += 1
        try:
            eid = int(elt.ID)
            ids.append(eid)
            if eid == 0 and ssid is None:
                raw = bytes(elt.info)
                ssid = raw.decode("utf-8", errors="replace") if raw else "<hidden>"
            elif eid == 48:
                akm = _parse_rsn_akm(bytes(elt.info))
        except (AttributeError, ValueError, TypeError):
            pass
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return ids, ssid, akm


def _parse_rsn_akm(rsn: bytes) -> str | None:
    """Pull the AKM suite out of an RSN IE — the thing that identifies WPA2 vs WPA3.

    Layout: version(2) group-cipher(4) pairwise-count(2) pairwise-suites(4*n)
            akm-count(2) akm-suites(4*n) rsn-caps(2)
    """
    try:
        if len(rsn) < 8:
            return None
        offset = 2 + 4                              # version + group cipher
        pair_count = int.from_bytes(rsn[offset : offset + 2], "little")
        offset += 2 + 4 * pair_count
        if offset + 2 > len(rsn):
            return None
        akm_count = int.from_bytes(rsn[offset : offset + 2], "little")
        offset += 2
        if akm_count < 1 or offset + 4 > len(rsn):
            return None
        suite_type = rsn[offset + 3]
        return {
            1: "802.1X",
            2: "PSK",
            8: "SAE",
            9: "FT-SAE",
            18: "OWE",
        }.get(suite_type, f"akm-{suite_type}")
    except (IndexError, ValueError):
        return None


def dissect_packet(pkt: Any, index: int, t0: float) -> Frame:
    """Convert one Scapy packet into a `Frame`."""
    if not pkt.haslayer(Dot11):
        return Frame(index=index, time_s=float(pkt.time) - t0, kind=FrameKind.OTHER,
                     subtype=-1, ftype=-1, length=len(pkt))

    d = pkt[Dot11]
    ftype = int(d.type)
    subtype = int(d.subtype)

    kind = FrameKind.OTHER
    if ftype == 0:
        kind = {
            0: FrameKind.ASSOC_REQUEST,
            1: FrameKind.ASSOC_RESPONSE,
            2: FrameKind.REASSOC_REQUEST,
            3: FrameKind.REASSOC_RESPONSE,
            4: FrameKind.PROBE_REQUEST,
            5: FrameKind.PROBE_RESPONSE,
            8: FrameKind.BEACON,
            10: FrameKind.DISASSOC,
            11: FrameKind.AUTH,
            12: FrameKind.DEAUTH,
        }.get(subtype, FrameKind.OTHER)
    elif ftype == 1:
        kind = FrameKind.CONTROL
    elif ftype == 2:
        kind = FrameKind.QOS_DATA if subtype & 0x08 else FrameKind.DATA

    flags = int(getattr(d, "FCfield", 0) or 0)
    frame = Frame(
        index=index,
        time_s=float(pkt.time) - t0,
        kind=kind,
        subtype=subtype,
        ftype=ftype,
        addr1=getattr(d, "addr1", None),
        addr2=getattr(d, "addr2", None),
        addr3=getattr(d, "addr3", None),
        seq=(int(d.SC) >> 4) if getattr(d, "SC", None) is not None else None,
        retry=bool(flags & 0x08),
        protected=bool(flags & 0x40),
        length=len(pkt),
        bad_fcs=_has_bad_fcs(pkt),
    )

    rssi = _radiotap_field(pkt, "dBm_AntSignal", "dbm_antsignal", "AntSignal")
    if rssi is not None:
        try:
            frame.rssi_dbm = int(rssi)
        except (TypeError, ValueError):
            pass
    freq = _radiotap_field(pkt, "ChannelFrequency", "Channel", "channel_freq")
    if freq is not None:
        try:
            frame.freq_mhz = int(freq)
        except (TypeError, ValueError):
            pass
    rate = _radiotap_field(pkt, "Rate", "rate")
    if rate is not None:
        try:
            frame.rate_mbps = float(rate) / 2.0    # radiotap Rate is in 500kbps units
        except (TypeError, ValueError):
            pass

    # ---- payload facts ----
    if pkt.haslayer(EAPOL):
        frame.kind, frame.key_info, frame.replay_counter = _classify_eapol(pkt)

    if pkt.haslayer(Dot11Auth):
        a = pkt[Dot11Auth]
        frame.auth_algo = int(a.algo)
        frame.auth_seq = int(a.seqnum)
        frame.status_code = int(a.status)
        if frame.auth_algo == AUTH_ALGO_SAE:
            # SAE message type is carried by the auth sequence number.
            frame.kind = FrameKind.SAE_COMMIT if frame.auth_seq == 1 else FrameKind.SAE_CONFIRM

    if pkt.haslayer(Dot11AssoResp):
        r = pkt[Dot11AssoResp]
        frame.status_code = int(r.status)
        frame.aid = int(r.AID) & 0x3FFF
    elif pkt.haslayer(Dot11ReassoResp):
        r = pkt[Dot11ReassoResp]
        frame.status_code = int(r.status)

    if pkt.haslayer(Dot11Deauth):
        frame.reason_code = int(pkt[Dot11Deauth].reason)
    elif pkt.haslayer(Dot11Disas):
        frame.reason_code = int(pkt[Dot11Disas].reason)

    if pkt.haslayer(Dot11Elt):
        frame.elements, ssid, akm = _extract_elements(pkt)
        frame.ssid = ssid
        frame.rsn_akm = akm

    return frame


# ---------------------------------------------------------------- capture


@dataclass
class Capture:
    """A dissected capture file."""

    path: Path
    frames: list[Frame]

    def __len__(self) -> int:
        return len(self.frames)

    def __iter__(self) -> Iterator[Frame]:
        return iter(self.frames)

    def of_kind(self, *kinds: FrameKind) -> list[Frame]:
        wanted = set(kinds)
        return [f for f in self.frames if f.kind in wanted]

    def first(self, *kinds: FrameKind) -> Frame | None:
        return next((f for f in self.frames if f.kind in set(kinds)), None)

    def counts(self) -> Counter[str]:
        return Counter(f.kind.value for f in self.frames)

    @property
    def duration_s(self) -> float:
        return self.frames[-1].time_s - self.frames[0].time_s if self.frames else 0.0

    @property
    def retry_rate(self) -> float:
        """Fraction of data frames marked as retransmissions.

        Data frames only: management frames retry for different reasons and mixing
        them in makes the number meaningless as a congestion signal.
        """
        data = [f for f in self.frames if f.ftype == 2]
        if not data:
            return 0.0
        return sum(1 for f in data if f.retry) / len(data)

    @property
    def rssi_values(self) -> list[int]:
        return [f.rssi_dbm for f in self.frames if f.rssi_dbm is not None]

    def rssi_trend(self) -> tuple[int, int] | None:
        """(first, last) RSSI — a collapsing signal precedes most disconnects."""
        vals = self.rssi_values
        return (vals[0], vals[-1]) if vals else None

    def bssids(self) -> list[str]:
        """BSSIDs seen, most frequent first."""
        counter: Counter[str] = Counter()
        for f in self.frames:
            if f.is_management and f.addr3:
                counter[f.addr3] += 1
        return [b for b, _ in counter.most_common()]


def load_capture(path: str | Path) -> Capture:
    """Read and dissect a .pcap file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"capture not found: {p}")
    packets = rdpcap(str(p))
    if not packets:
        return Capture(path=p, frames=[])
    t0 = float(packets[0].time)
    return Capture(path=p, frames=[dissect_packet(pkt, i + 1, t0) for i, pkt in enumerate(packets)])


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="dissect an 802.11 capture")
    ap.add_argument("pcap")
    ap.add_argument("--kind", help="show only this frame kind")
    args = ap.parse_args()

    cap = load_capture(args.pcap)
    print(f"{cap.path.name}: {len(cap)} frames over {cap.duration_s:.3f}s")
    print(f"retry rate: {cap.retry_rate:.1%}   bssids: {', '.join(cap.bssids()) or 'none'}")
    trend = cap.rssi_trend()
    if trend:
        print(f"rssi: {trend[0]} -> {trend[1]} dBm")
    print("\ncounts:", dict(cap.counts()))
    print()
    for f in cap:
        if args.kind and f.kind.value != args.kind:
            continue
        print(f.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
