"""The DUT abstraction — the most important interface in the project.

A **DUT** ("Device Under Test") is whatever we are testing. In a real Apple lab it
is an iPhone in an RF chamber wired to a controllable access point. Here it is
either a deterministic C++ simulator or the actual Wi-Fi card in this MacBook.

The entire point of this module is that **the test suite never knows which.**
Tests are written against the `DUT` protocol below, and the same `pytest` run can
target either backend by changing one command-line flag:

    pytest --dut=sim      # deterministic simulator, runs anywhere, injectable faults
    pytest --dut=macos    # the real Wi-Fi card in this machine

Why this matters, and why interviewers ask about it
---------------------------------------------------
Without an abstraction you end up with two parallel test suites that drift apart,
and the expensive one (real hardware) is always the less-tested one. With it, a
test written once runs on every backend, and adding a third backend (a real
router over SSH, an Android phone over ADB) costs one file instead of a rewrite.

The hard part is not writing the interface — it is the **capability problem.**
Backends are genuinely not equal: the simulator can be ordered to fail its 4-way
handshake, and a real Wi-Fi card cannot. There are three ways to handle that, and
only one is right:

1. Lowest common denominator — only expose what every backend supports. Throws
   away the simulator's entire value.
2. Pretend, and let unsupported calls fail confusingly. A test that errors with
   `AttributeError` tells you nothing about coverage.
3. **Declare capabilities explicitly, and skip with a reason.** A skipped test
   with "macos cannot inject faults" is honest, greppable, and shows up in the
   report as a known gap rather than as false confidence.

This module implements (3). `Capability` is the vocabulary, `DUT.capabilities`
is the declaration, and `tests/plugin.py` enforces it at collection time.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

# ---------------------------------------------------------------- vocabulary
#
# These enums mirror the C++ enums in sim/include/airframe/types.hpp. The string
# values are the wire format shared by the control protocol, the database and the
# test IDs, so they are part of the contract and must not be casually renamed.


class Band(str, enum.Enum):
    GHZ_2_4 = "2.4GHz"
    GHZ_5 = "5GHz"
    GHZ_6 = "6GHz"


class Security(str, enum.Enum):
    OPEN = "open"
    WPA2_PSK = "wpa2_psk"
    WPA3_SAE = "wpa3_sae"
    WPA2_ENTERPRISE = "wpa2_enterprise"


class Phy(str, enum.Enum):
    DOT11N = "11n"
    DOT11AC = "11ac"
    DOT11AX = "11ax"
    DOT11BE = "11be"


class State(str, enum.Enum):
    IDLE = "IDLE"
    SCANNING = "SCANNING"
    AUTHENTICATING = "AUTHENTICATING"
    ASSOCIATING = "ASSOCIATING"
    FOURWAY = "FOURWAY_HANDSHAKE"
    DHCP = "DHCP"
    CONNECTED = "CONNECTED"
    ROAMING = "ROAMING"
    DISCONNECTING = "DISCONNECTING"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class Fault(str, enum.Enum):
    NONE = "NONE"
    AUTH_TIMEOUT = "AUTH_TIMEOUT"
    ASSOC_REJECT = "ASSOC_REJECT"
    FOURWAY_M3_TIMEOUT = "FOURWAY_M3_TIMEOUT"
    PMK_MISMATCH = "PMK_MISMATCH"
    DHCP_NAK = "DHCP_NAK"
    BEACON_LOSS = "BEACON_LOSS"
    DEAUTH = "DEAUTH"
    LOW_RSSI = "LOW_RSSI"
    CHANNEL_BUSY = "CHANNEL_BUSY"
    ROAM_PINGPONG = "ROAM_PINGPONG"
    SCAN_EMPTY = "SCAN_EMPTY"


class Capability(str, enum.Enum):
    """What a backend can actually do.

    Tests declare requirements with ``@pytest.mark.requires_capability(...)`` and
    are skipped — with the backend named in the reason — when unavailable.
    """

    FAULT_INJECTION = "fault_injection"      # can be told to fail in a specific way
    PACKET_CAPTURE = "packet_capture"        # produces a .pcap of the exchange
    DETERMINISTIC = "deterministic"          # same seed, same bytes, every time
    ROAMING = "roaming"                      # can be made to roam between BSSes
    RECONFIGURE = "reconfigure"              # band/security/PHY are choosable
    REAL_TRAFFIC = "real_traffic"            # can move real bytes over a real network
    SYSTEM_LOGS = "system_logs"              # exposes OS-level wireless logs
    SIX_GHZ = "six_ghz"                      # 6 GHz radio available


# ---------------------------------------------------------------- data shapes
#
# Both backends return these identical shapes. That is what lets an assertion
# written against the simulator run unchanged against real hardware.


@dataclass(frozen=True)
class StageTimings:
    """Per-stage durations of a connection attempt, in milliseconds.

    These are the highest-value diagnostic in the whole project: a slow
    connection is a completely different bug depending on *which* stage was slow.
    A long `dhcp_ms` with fast everything else points at the network; a long
    `fourway_ms` points at the supplicant or the credentials.
    """

    scan_ms: int = 0
    auth_ms: int = 0
    assoc_ms: int = 0
    fourway_ms: int = 0
    dhcp_ms: int = 0
    total_ms: int = 0

    @property
    def slowest_stage(self) -> str:
        stages = {
            "scan": self.scan_ms,
            "auth": self.auth_ms,
            "assoc": self.assoc_ms,
            "fourway": self.fourway_ms,
            "dhcp": self.dhcp_ms,
        }
        return max(stages, key=lambda k: stages[k])

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StageTimings:
        return cls(**{k: int(d.get(k, 0)) for k in cls.__dataclass_fields__})


@dataclass(frozen=True)
class ScanResult:
    ssid: str
    bssid: str
    band: Band = Band.GHZ_5
    channel: int = 0
    width_mhz: int = 0
    phy: Phy = Phy.DOT11AX
    security: Security = Security.WPA2_PSK
    rssi_dbm: int = 0

    @property
    def is_usable(self) -> bool:
        """Above roughly -80 dBm a link is workable; below it, marginal at best."""
        return self.rssi_dbm > -80


@dataclass(frozen=True)
class ConnectResult:
    ok: bool
    final_state: State = State.UNKNOWN
    fault: Fault = Fault.NONE
    status_code: int = 0
    status_name: str = ""
    reason_code: int = 0
    reason_name: str = ""
    failed_at: State = State.IDLE
    timings: StageTimings = field(default_factory=StageTimings)
    message: str = ""
    bssid: str = ""
    ip_address: str = ""

    @property
    def connected(self) -> bool:
        return self.ok and self.final_state is State.CONNECTED

    def describe(self) -> str:
        """One line suitable for a pytest assertion message or a bug title."""
        if self.ok:
            return (
                f"connected to {self.bssid} in {self.timings.total_ms}ms "
                f"(ip={self.ip_address or 'n/a'})"
            )
        detail = self.reason_name if self.reason_code else self.status_name
        return (
            f"failed at {self.failed_at.value}"
            f"{f' [{detail}]' if detail else ''}: {self.message}"
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ConnectResult:
        def as_enum(enum_cls: Any, raw: Any, default: Any) -> Any:
            try:
                return enum_cls(raw)
            except (ValueError, KeyError):
                return default

        return cls(
            ok=bool(d.get("ok", False)),
            final_state=as_enum(State, d.get("final_state"), State.UNKNOWN),
            fault=as_enum(Fault, d.get("fault"), Fault.NONE),
            status_code=int(d.get("status_code", 0)),
            status_name=str(d.get("status_name", "")),
            reason_code=int(d.get("reason_code", 0)),
            reason_name=str(d.get("reason_name", "")),
            failed_at=as_enum(State, d.get("failed_at"), State.IDLE),
            timings=StageTimings.from_dict(d.get("timings", {})),
            message=str(d.get("message", "")),
            bssid=str(d.get("bssid", "")),
            ip_address=str(d.get("ip_address", "")),
        )


@dataclass(frozen=True)
class LinkStats:
    rssi_dbm: int = 0
    noise_dbm: int = -95
    snr_db: int = 0
    channel: int = 0
    width_mhz: int = 0
    tx_rate_mbps: int = 0
    tx_frames: int = 0
    rx_frames: int = 0
    tx_retries: int = 0
    retry_rate: float = 0.0

    @property
    def link_quality(self) -> str:
        """Coarse SNR bucket. Thresholds are the usual field rules of thumb."""
        if self.snr_db >= 40:
            return "excellent"
        if self.snr_db >= 25:
            return "good"
        if self.snr_db >= 15:
            return "fair"
        return "poor"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LinkStats:
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass(frozen=True)
class NetworkConfig:
    """What to connect to. The simulator invents it; macOS reads it from reality."""

    ssid: str = "airframe-test-ap"
    security: Security = Security.WPA2_PSK
    band: Band = Band.GHZ_5
    channel: int = 36
    width_mhz: int = 80
    phy: Phy = Phy.DOT11AX

    def test_id(self) -> str:
        """Compact identifier used in parametrized test IDs, e.g. ``5GHz-80-wpa3_sae-11ax``."""
        return f"{self.band.value}-{self.width_mhz}-{self.security.value}-{self.phy.value}"

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for key in ("security", "band", "phy"):
            d[key] = getattr(self, key).value
        return d


class DUTError(RuntimeError):
    """A backend failed to carry out an instruction (transport, spawn, parse)."""


class UnsupportedOperation(DUTError):
    """The backend does not have the capability this operation requires."""


# ---------------------------------------------------------------- the interface


class DUT(ABC):
    """A wireless device under test.

    Implementations must be usable as a context manager, and `close()` must be
    safe to call more than once — pytest teardown runs even after a failure, and
    a fixture that raises during cleanup masks the real error.
    """

    #: short backend name, used in run records and skip reasons
    backend: str = "abstract"

    # ---- capability declaration ----

    @property
    @abstractmethod
    def capabilities(self) -> frozenset[Capability]:
        """Everything this backend can do. Checked at collection time."""

    def supports(self, cap: Capability | str) -> bool:
        if isinstance(cap, str):
            try:
                cap = Capability(cap)
            except ValueError:
                return False
        return cap in self.capabilities

    def require(self, cap: Capability | str) -> None:
        """Raise `UnsupportedOperation` unless the capability is present."""
        if not self.supports(cap):
            name = cap.value if isinstance(cap, Capability) else cap
            raise UnsupportedOperation(f"backend {self.backend!r} cannot {name}")

    # ---- identity ----

    @abstractmethod
    def identity(self) -> str:
        """Human-readable description, recorded against every run."""

    # ---- operations ----

    @abstractmethod
    def scan(self) -> list[ScanResult]:
        """Return visible networks. May be empty."""

    @abstractmethod
    def connect(self, config: NetworkConfig | None = None) -> ConnectResult:
        """Attempt to associate. Returns a result rather than raising on failure —
        a failed connection is data, not an exception."""

    @abstractmethod
    def disconnect(self) -> None:
        """Tear the link down. Must be safe when already disconnected."""

    @abstractmethod
    def state(self) -> State:
        """Current link state."""

    @abstractmethod
    def stats(self) -> LinkStats:
        """Current radio and traffic statistics."""

    # ---- optional operations, gated on capabilities ----

    def inject_fault(self, fault: Fault, probability: float = 1.0, code: int = 0) -> None:
        self.require(Capability.FAULT_INJECTION)
        raise NotImplementedError

    def roam(self) -> ConnectResult:
        self.require(Capability.ROAMING)
        raise NotImplementedError

    def run_traffic(self, duration_ms: int) -> bool:
        """Exercise the link for a while. Returns False if it dropped."""
        raise NotImplementedError

    def logs(self) -> list[str]:
        """Wireless log lines produced since the session started."""
        return []

    def capture_path(self) -> str | None:
        """Path to a .pcap for this session, when the backend produces one."""
        return None

    def reset(self) -> None:
        """Return to a known-idle state, ready for the next test."""
        self.disconnect()

    # ---- lifecycle ----

    def close(self) -> None:
        """Release resources. Must be idempotent."""

    def __enter__(self) -> DUT:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
