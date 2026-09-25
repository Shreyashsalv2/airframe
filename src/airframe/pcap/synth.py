"""Scapy-based frame synthesis — captures the C++ simulator deliberately cannot make.

The simulator models a *well-behaved* station and AP. That is the right choice for
it: a DUT that emits malformed frames would make every downstream assertion
ambiguous. But a packet analyser must also be tested against traffic that is
hostile or broken, and those cases have to come from somewhere.

So this module builds, with Scapy:

* **attack traffic** — deauth floods, spoofed disassociation, a KRACK-style M3
  replay,
* **malformed frames** — truncated information elements, a length field that lies,
  an RSN IE claiming an impossible cipher,
* **edge cases** — hidden SSIDs, zero-length SSIDs, IE chains long enough to catch
  a parser that lacks a loop guard.

This is negative testing, and it is the half of testing people skip. A dissector
that handles only valid input is not finished; it is untested. Anything reachable
from the air is attacker-controlled, so "what happens on garbage input" is a
correctness question, not a robustness nicety.
"""

from __future__ import annotations

import warnings
from pathlib import Path

warnings.filterwarnings("ignore", message=r".*(cryptography|Diffie-Hellman|FFDH).*")

from scapy.all import RadioTap, wrpcap  # noqa: E402
from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
)
from scapy.layers.eap import EAPOL  # noqa: E402
from scapy.layers.l2 import LLC, SNAP  # noqa: E402

# Locally-administered MACs, so nothing here can be mistaken for real hardware.
AP = "02:aa:bb:cc:dd:ee"
STA = "02:11:22:33:44:55"
ROGUE = "02:de:ad:be:ef:01"
BROADCAST = "ff:ff:ff:ff:ff:ff"


def _radio(rssi: int = -45, freq: int = 5180) -> RadioTap:
    return RadioTap(present="Flags+Rate+Channel+dBm_AntSignal", Flags="",
                    Rate=12, ChannelFrequency=freq, dBm_AntSignal=rssi)


def beacon(ssid: str = "synth-ap", *, rssi: int = -45, akm: int = 2) -> object:
    """A well-formed beacon, as the control case for the malformed ones."""
    rsn = (
        b"\x01\x00"                      # RSN version 1
        b"\x00\x0f\xac\x04"              # group cipher CCMP
        b"\x01\x00\x00\x0f\xac\x04"      # 1 pairwise: CCMP
        + b"\x01\x00\x00\x0f\xac" + bytes([akm])   # 1 AKM
        + b"\x80\x00"                    # RSN capabilities: MFP capable
    )
    return (
        _radio(rssi)
        / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=AP, addr3=AP)
        / Dot11Beacon(cap="ESS+privacy", beacon_interval=100)
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=1, info=b"\x8c\x12\x98\x24\xb0\x48\x60\x6c")
        / Dot11Elt(ID=3, info=b"\x24")
        / Dot11Elt(ID=48, info=rsn)
    )


def deauth_flood(count: int = 20, *, spoofed: bool = True) -> list[object]:
    """A deauth flood: the classic Wi-Fi denial of service.

    Trivial to mount against WPA2 because deauthentication frames are
    unauthenticated — anyone can forge one claiming to be the AP. This is exactly
    the attack WPA3's mandatory Management Frame Protection prevents, which is the
    most concrete reason to care about WPA3 at all.
    """
    src = ROGUE if spoofed else AP
    return [
        _radio(-52)
        / Dot11(type=0, subtype=12, addr1=STA, addr2=src, addr3=AP)
        / Dot11Deauth(reason=7)
        for _ in range(count)
    ]


def spoofed_disassoc(count: int = 8) -> list[object]:
    return [
        _radio(-55)
        / Dot11(type=0, subtype=10, addr1=BROADCAST, addr2=ROGUE, addr3=AP)
        / Dot11Disas(reason=8)
        for _ in range(count)
    ]


def _eapol_key(message: int, *, replay: int = 1, nonce: bytes | None = None) -> bytes:
    """Build an EAPOL-Key body for M1..M4."""
    key_info = {1: 0x008A, 2: 0x010A, 3: 0x13CA, 4: 0x030A}[message]
    body = bytearray()
    body += b"\x02"                                   # descriptor type: RSN
    body += key_info.to_bytes(2, "big")
    body += (16).to_bytes(2, "big")                   # key length
    body += replay.to_bytes(8, "big")
    body += (nonce or bytes([message]) * 32)[:32].ljust(32, b"\x00")
    body += b"\x00" * 16                              # key IV
    body += b"\x00" * 8                               # key RSC
    body += b"\x00" * 8                               # reserved
    body += (b"\x00" * 16) if message == 1 else (b"\xab" * 16)   # MIC
    if message == 3:
        gtk = b"\xcd" * 56
        body += len(gtk).to_bytes(2, "big") + gtk
    else:
        body += (0).to_bytes(2, "big")
    return bytes(body)


# Scapy renamed the Dot11 FCfield flags between versions: 2.6 and earlier used
# "to-DS"/"from-DS", 2.7 uses "to_DS"/"from_DS". Passing the wrong spelling raises
# ValueError at construction. Resolve the names from Scapy itself rather than
# hardcoding either spelling -- the library already knows, so ask it.
def _fc_flag(*candidates: str) -> str:
    names = Dot11().get_field("FCfield").names
    for candidate in candidates:
        if candidate in names:
            return candidate
    raise RuntimeError(f"none of {candidates} are Dot11 FCfield flags; scapy has {names}")


_TO_DS = _fc_flag("to_DS", "to-DS")
_FROM_DS = _fc_flag("from_DS", "from-DS")


def eapol_frame(message: int, *, replay: int = 1, nonce: bytes | None = None) -> object:
    # ToDS/FromDS decide how addr1..addr3 are interpreted:
    #   STA -> AP (ToDS)  : addr1=BSSID, addr2=STA,   addr3=destination
    #   AP -> STA (FromDS): addr1=STA,   addr2=BSSID, addr3=source
    to_ds = message in (2, 4)
    dot11 = (
        Dot11(type=2, subtype=0, FCfield=_TO_DS, addr1=AP, addr2=STA, addr3=AP)
        if to_ds
        else Dot11(type=2, subtype=0, FCfield=_FROM_DS, addr1=STA, addr2=AP, addr3=AP)
    )
    body = _eapol_key(message, replay=replay, nonce=nonce)
    # An 802.11 data frame carrying EAPOL needs an LLC/SNAP header announcing
    # EtherType 0x888E (802.1X). Scapy does NOT insert it for you when you stack
    # Dot11/EAPOL directly -- the frame still serialises, but every standard
    # dissector reads it as raw LLC and the EAPOL is invisible. The C++ builder in
    # sim/src/frame.cpp gets this right; this helper did not. See BUILD_JOURNAL #12.
    return (
        _radio()
        / dot11
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x000000, code=0x888E)
        / EAPOL(version=2, type=3, len=len(body))
        / body
    )


def krack_m3_replay(replays: int = 4) -> list[object]:
    """A KRACK-style M3 replay.

    CVE-2017-13077 and friends: replaying handshake message 3 makes a vulnerable
    client reinstall the pairwise key, resetting its nonce counter and allowing
    keystream reuse. The observable signature is repeated M3s carrying *increasing
    replay counters* while the handshake has already completed — which is what a
    detector can key on without needing to decrypt anything.
    """
    frames = [eapol_frame(1), eapol_frame(2), eapol_frame(3), eapol_frame(4)]
    for i in range(replays):
        frames.append(eapol_frame(3, replay=2 + i))
    return frames


# ---------------------------------------------------------------- malformed

def truncated_ie_beacon() -> object:
    """An IE whose length field claims more bytes than the frame contains.

    A parser that trusts the length field walks off the end of the buffer. In C
    that is a buffer overread; in Python it is an exception that takes down the
    analysis of an otherwise-good capture.
    """
    return (
        _radio()
        / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=AP, addr3=AP)
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, len=32, info=b"short")      # claims 32 bytes, carries 5
    )


def zero_length_ssid_beacon() -> object:
    """A hidden network: a zero-length SSID element is legal and easy to mishandle."""
    return (
        _radio()
        / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=AP, addr3=AP)
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=b"")
        / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
    )


def bogus_rsn_beacon() -> object:
    """An RSN IE advertising a cipher suite that does not exist."""
    return (
        _radio()
        / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=AP, addr3=AP)
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID=0, info=b"bogus-rsn")
        / Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\xff\x01\x00\x00\x0f\xac\xfe\x01\x00"
                                b"\x00\x0f\xac\xfd\x00\x00")
    )


def long_ie_chain_beacon(elements: int = 120) -> object:
    """A beacon with an absurd number of IEs, to prove the parser has a loop guard.

    A dissector that walks the IE chain without a bound can be made to spin on a
    crafted frame — a cheap denial of service against the analysis tooling itself.
    """
    pkt = (
        _radio()
        / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=AP, addr3=AP)
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=b"long-chain")
    )
    for i in range(elements):
        pkt = pkt / Dot11Elt(ID=221, info=bytes([i % 256]) * 4)
    return pkt


# ---------------------------------------------------------------- corpora

def write_corpus(out_dir: str | Path) -> dict[str, Path]:
    """Write every synthetic capture. Returns {name: path}."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    corpus: dict[str, list[object]] = {
        "synth_clean_beacon": [beacon()],
        "synth_deauth_flood": [beacon(), *deauth_flood(20)],
        "synth_spoofed_disassoc": [beacon(), *spoofed_disassoc(8)],
        "synth_krack_m3_replay": [beacon(), *krack_m3_replay(4)],
        "synth_truncated_ie": [truncated_ie_beacon()],
        "synth_hidden_ssid": [zero_length_ssid_beacon()],
        "synth_bogus_rsn": [bogus_rsn_beacon()],
        "synth_long_ie_chain": [long_ie_chain_beacon(120)],
        "synth_wpa3_beacon": [beacon("synth-wpa3", akm=8)],
        "synth_mixed_hostile": [
            beacon(),
            *deauth_flood(6),
            *spoofed_disassoc(4),
            truncated_ie_beacon(),
            bogus_rsn_beacon(),
        ],
    }
    written: dict[str, Path] = {}
    for name, frames in corpus.items():
        path = out / f"{name}.pcap"
        wrpcap(str(path), frames)
        written[name] = path
    return written


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="generate synthetic 802.11 captures")
    ap.add_argument("--out", default="data/pcaps", help="output directory")
    args = ap.parse_args()

    written = write_corpus(args.out)
    for name, path in written.items():
        print(f"{name:<26} {path}  ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
