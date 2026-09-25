"""Real-hardware backend — this MacBook's actual Wi-Fi interface.

This is the backend that makes the project more than a simulation exercise: the
same tests that run against the C++ simulator also read genuine RSSI, noise,
channel width, PHY mode and negotiated rate from the real radio.

What macOS actually allows in 2026 (all of this was verified on this machine, not
assumed — see BUILD_JOURNAL.md #6)
---------------------------------------------------------------------------------
* The classic ``airport`` CLI is **gone.** It lived in a private framework, was
  deprecated in macOS 14 and has since been removed outright. Every tutorial
  older than about two years tells you to use it.
* ``wdutil info`` is the modern replacement and **requires sudo.** We try it, and
  fall through cleanly when it refuses rather than prompting mid-test-run.
* ``system_profiler -json SPAirPortDataType`` needs **no privileges** and is the
  workhorse here. It reports channel, band, width, RSSI, noise, PHY mode and rate.
* ``networksetup -getairportnetwork`` reports "not associated" even while
  connected, so it is not trusted as a source of truth.
* **The SSID comes back as ``<redacted>``** unless the calling process holds
  Location Services permission. Network *names* are location-inferring data on
  modern macOS. Everything else is still readable — so the backend reports an
  honest ``<redacted>`` rather than pretending it knows.

Consequences for the abstraction
--------------------------------
This backend declares a deliberately small capability set. It cannot inject
faults, cannot be told to use WPA2 instead of WPA3, cannot capture packets
without monitor mode, and cannot be forced to roam. Tests requiring those are
skipped with the reason stated, which is the honest outcome — see the capability
discussion in ``dut/base.py``.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from typing import Any

from airframe.dut.base import (
    DUT,
    Band,
    Capability,
    ConnectResult,
    LinkStats,
    NetworkConfig,
    Phy,
    ScanResult,
    Security,
    StageTimings,
    State,
    UnsupportedOperation,
)

REDACTED = "<redacted>"


def _run(cmd: list[str], timeout: float = 15.0) -> tuple[int, str, str]:
    """Run a command, never raise. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"
    except OSError as exc:
        return 1, "", str(exc)


# ---------------------------------------------------------------- parsing
#
# These parsers are separated from the subprocess calls so they can be unit
# tested against captured fixture strings — you cannot write a reliable test
# against live Wi-Fi state, because it changes underneath you.


def parse_channel_field(raw: str) -> tuple[int, Band | None, int]:
    """Parse ``system_profiler``'s channel string.

    >>> parse_channel_field("149 (5GHz, 80MHz)")
    (149, <Band.GHZ_5: '5GHz'>, 80)
    >>> parse_channel_field("6 (2.4GHz, 20MHz)")
    (6, <Band.GHZ_2_4: '2.4GHz'>, 20)
    >>> parse_channel_field("")
    (0, None, 0)
    """
    if not raw:
        return 0, None, 0
    m = re.match(r"\s*(\d+)", raw)
    channel = int(m.group(1)) if m else 0

    band: Band | None = None
    if "6GHz" in raw:
        band = Band.GHZ_6
    elif "5GHz" in raw:
        band = Band.GHZ_5
    elif "2.4GHz" in raw:
        band = Band.GHZ_2_4

    wm = re.search(r"(\d+)MHz", raw)
    width = int(wm.group(1)) if wm else 0
    return channel, band, width


def parse_signal_noise(raw: str) -> tuple[int, int]:
    """Parse ``"-64 dBm / -89 dBm"`` into ``(rssi, noise)``.

    >>> parse_signal_noise("-64 dBm / -89 dBm")
    (-64, -89)
    >>> parse_signal_noise("garbage")
    (0, -95)
    """
    nums = re.findall(r"(-?\d+)\s*dBm", raw or "")
    if len(nums) >= 2:
        return int(nums[0]), int(nums[1])
    if len(nums) == 1:
        return int(nums[0]), -95
    return 0, -95


def parse_phy_mode(raw: str) -> Phy:
    """Map ``"802.11ac"`` and friends onto our Phy enum, newest match first."""
    r = (raw or "").lower()
    if "be" in r or "wi-fi 7" in r:
        return Phy.DOT11BE
    if "ax" in r or "wi-fi 6" in r:
        return Phy.DOT11AX
    if "ac" in r:
        return Phy.DOT11AC
    return Phy.DOT11N


def parse_security_mode(raw: str) -> Security:
    """Map the ``spairport_security_mode_*`` vocabulary onto our Security enum."""
    r = (raw or "").lower()
    if "sae" in r or "wpa3" in r:
        return Security.WPA3_SAE
    if "enterprise" in r or "8021x" in r or "802.1x" in r:
        return Security.WPA2_ENTERPRISE
    if "wpa2" in r or "wpa_personal" in r or "psk" in r:
        return Security.WPA2_PSK
    return Security.OPEN


class MacOSDUT(DUT):
    """The real Wi-Fi interface on this machine, read-only."""

    backend = "macos"

    # Process-wide cache, deliberately NOT per-instance.
    #
    # `system_profiler` takes 2-5 seconds per invocation, and the test suite
    # creates a fresh DUT per test for isolation. Per-instance caching therefore
    # cached nothing useful and a 14-test run took 65 seconds.
    #
    # Sharing the cache across instances is not a cheat here: there is exactly one
    # Wi-Fi radio on the machine, so its state is genuinely global. Two DUT objects
    # observing the same interface *should* see the same answer. The short TTL
    # keeps readings fresh enough that RSSI still moves between tests.
    _shared_cache: dict[str, dict[str, Any]] = {}
    _shared_cache_at: dict[str, float] = {}

    def __init__(self, interface: str = "en0", *, artifact_dir: str | None = None) -> None:
        if sys.platform != "darwin":
            raise UnsupportedOperation(
                f"MacOSDUT requires macOS, this is {sys.platform!r}. Use --dut=sim."
            )
        self.interface = interface
        self.artifact_dir = artifact_dir
        self._session_start = time.time()
        self._cache_ttl = 3.0     # system_profiler costs seconds; re-read sparingly
        self._sudo_wdutil_unavailable = False

    # ---------------------------------------------------------------- sources

    def _airport_info(self, *, force: bool = False) -> dict[str, Any]:
        """Current network info via `system_profiler`, cached briefly."""
        now = time.time()
        key = self.interface
        if (
            not force
            and key in self._shared_cache
            and (now - self._shared_cache_at.get(key, 0.0)) < self._cache_ttl
        ):
            return self._shared_cache[key]

        rc, out, _ = _run(["system_profiler", "-json", "SPAirPortDataType"], timeout=25.0)
        info: dict[str, Any] = {}
        if rc == 0 and out:
            try:
                data = json.loads(out)
                for entry in data.get("SPAirPortDataType", []):
                    for iface in entry.get("spairport_airport_interfaces", []):
                        if iface.get("_name") != self.interface:
                            continue
                        info["interface"] = iface
                        cur = iface.get("spairport_current_network_information")
                        if cur:
                            info["current"] = cur
                    sw = entry.get("spairport_software_information")
                    if sw:
                        info["software"] = sw
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass

        type(self)._shared_cache[key] = info
        type(self)._shared_cache_at[key] = now
        return info

    def _wdutil_info(self) -> dict[str, str]:
        """Try `wdutil info`. Returns {} when sudo is unavailable — never prompts.

        `sudo -n` means "non-interactive": fail immediately rather than asking for
        a password. A test suite that blocks on a hidden password prompt is a test
        suite that hangs in CI.
        """
        if self._sudo_wdutil_unavailable:
            return {}
        rc, out, _ = _run(["sudo", "-n", "wdutil", "info"], timeout=20.0)
        if rc != 0 or not out:
            self._sudo_wdutil_unavailable = True
            return {}
        fields: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                fields[k.strip().lower()] = v.strip()
        return fields

    def _ifconfig(self) -> dict[str, str]:
        rc, out, _ = _run(["ifconfig", self.interface])
        if rc != 0:
            return {}
        result: dict[str, str] = {}
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            result["ipv4"] = m.group(1)
        m = re.search(r"\bether ([0-9a-f:]{17})", out)
        if m:
            result["mac"] = m.group(1)
        m = re.search(r"\bstatus: (\w+)", out)
        if m:
            result["status"] = m.group(1)
        return result

    def gateway(self) -> str | None:
        """Default gateway — the control endpoint that separates Wi-Fi problems
        from ISP problems in the KPI suite."""
        rc, out, _ = _run(["route", "-n", "get", "default"])
        if rc != 0:
            return None
        m = re.search(r"gateway:\s*(\S+)", out)
        return m.group(1) if m else None

    # ---------------------------------------------------------------- DUT API

    @property
    def capabilities(self) -> frozenset[Capability]:
        caps = {Capability.REAL_TRAFFIC, Capability.SYSTEM_LOGS}
        # 6 GHz is a hardware fact, so detect it rather than assuming.
        info = self._airport_info()
        iface = info.get("interface", {})
        supported = json.dumps(iface.get("spairport_supported_channels", "")) or ""
        if "6GHz" in supported or self._current_band() is Band.GHZ_6:
            caps.add(Capability.SIX_GHZ)
        # Deliberately absent: FAULT_INJECTION, PACKET_CAPTURE, DETERMINISTIC,
        # ROAMING, RECONFIGURE. A real card does none of those on command.
        return frozenset(caps)

    def _current(self) -> dict[str, Any]:
        return self._airport_info().get("current", {}) or {}

    def _current_band(self) -> Band | None:
        _, band, _ = parse_channel_field(str(self._current().get("spairport_network_channel", "")))
        return band

    def identity(self) -> str:
        info = self._airport_info()
        sw = info.get("software", {})
        cur = self._current()
        ssid = str(cur.get("_name") or "not-associated")
        band = self._current_band()
        return (
            f"macos({self.interface}, ssid={ssid}, "
            f"band={band.value if band else 'n/a'}, "
            f"corewlan={sw.get('spairport_corewlan_version', '?')})"
        )

    def ssid(self) -> str:
        """Current SSID, or ``<redacted>`` when macOS withholds it."""
        return str(self._current().get("_name") or "not-associated")

    def scan(self) -> list[ScanResult]:
        """Report the currently-associated network.

        Note this is **not** a true scan. Modern macOS offers no unprivileged way
        to trigger one and read the results, so rather than shell out to something
        that needs sudo, this returns what is observable. The method is honest
        about that instead of faking neighbouring BSSes.
        """
        cur = self._current()
        if not cur:
            return []
        channel, band, width = parse_channel_field(str(cur.get("spairport_network_channel", "")))
        rssi, _noise = parse_signal_noise(str(cur.get("spairport_signal_noise", "")))
        return [
            ScanResult(
                ssid=str(cur.get("_name") or REDACTED),
                bssid=REDACTED,        # BSSID is withheld alongside the SSID
                band=band or Band.GHZ_5,
                channel=channel,
                width_mhz=width,
                phy=parse_phy_mode(str(cur.get("spairport_network_phymode", ""))),
                security=parse_security_mode(str(cur.get("spairport_security_mode", ""))),
                rssi_dbm=rssi,
            )
        ]

    def connect(self, config: NetworkConfig | None = None) -> ConnectResult:
        """Report on the existing association; does not initiate one.

        Joining a *specific* network programmatically needs credentials and the
        CoreWLAN API, which is out of scope and would require storing a
        passphrase. What this does instead is genuinely useful: it observes the
        live link and returns it in the same shape the simulator uses, so
        assertions about a healthy link work identically on both backends.
        """
        if config is not None:
            # Refusing loudly beats silently ignoring the request and returning a
            # result about a different network than the test asked for.
            raise UnsupportedOperation(
                "macos backend cannot select a network; it observes the current one. "
                "Use --dut=sim for configuration-driven tests."
            )

        t0 = time.time()
        cur = self._current()
        net = self._ifconfig()
        elapsed_ms = int((time.time() - t0) * 1000)

        if not cur:
            return ConnectResult(
                ok=False,
                final_state=State.IDLE,
                failed_at=State.SCANNING,
                message=f"{self.interface} is not associated with any network",
                timings=StageTimings(total_ms=elapsed_ms),
            )

        ip = net.get("ipv4", "")
        return ConnectResult(
            ok=bool(ip),
            final_state=State.CONNECTED if ip else State.DHCP,
            status_name="SUCCESS" if ip else "",
            message=(
                f"associated with {cur.get('_name') or REDACTED}"
                if ip
                else "associated but no IPv4 address"
            ),
            bssid=REDACTED,
            ip_address=ip,
            timings=StageTimings(total_ms=elapsed_ms),
        )

    def disconnect(self) -> None:
        """Deliberately a no-op.

        The obvious implementation is ``networksetup -setairportpower en0 off``,
        which would drop the user's internet — including the connection this
        session is running over. A test backend must never sabotage the machine it
        is running on, so this refuses to act rather than being "helpful".
        """
        return

    def state(self) -> State:
        cur = self._current()
        if not cur:
            return State.IDLE
        return State.CONNECTED if self._ifconfig().get("ipv4") else State.DHCP

    def stats(self) -> LinkStats:
        cur = self._current()
        if not cur:
            return LinkStats()
        channel, _band, width = parse_channel_field(str(cur.get("spairport_network_channel", "")))
        rssi, noise = parse_signal_noise(str(cur.get("spairport_signal_noise", "")))
        try:
            rate = int(cur.get("spairport_network_rate", 0) or 0)
        except (TypeError, ValueError):
            rate = 0
        return LinkStats(
            rssi_dbm=rssi,
            noise_dbm=noise,
            snr_db=rssi - noise,
            channel=channel,
            width_mhz=width,
            tx_rate_mbps=rate,
            # Frame and retry counters need driver-level access we do not have
            # without sudo, so they are honestly left at zero rather than faked.
            tx_frames=0,
            rx_frames=0,
            tx_retries=0,
            retry_rate=0.0,
        )

    def run_traffic(self, duration_ms: int) -> bool:
        """Hold the link and confirm it is still up afterwards.

        Unlike the simulator this does not synthesise frames — the KPI layer moves
        the real bytes. Here we simply verify the link survived.
        """
        time.sleep(min(duration_ms / 1000.0, 10.0))
        return self.state() is State.CONNECTED

    def logs(self) -> list[str]:
        """Real wireless logs from the unified logging system.

        ``log show`` is slow and its predicate syntax is fussy; the window is kept
        tight and failures degrade to an empty list rather than an exception,
        because missing logs must not fail an otherwise-good test.
        """
        seconds = max(int(time.time() - self._session_start) + 5, 10)
        rc, out, _ = _run(
            [
                "log", "show",
                "--last", f"{seconds}s",
                "--style", "compact",
                "--predicate",
                'subsystem == "com.apple.wifi" OR process == "wifid" '
                'OR process == "airportd"',
            ],
            timeout=45.0,
        )
        if rc != 0 or not out:
            return []
        return [line for line in out.splitlines() if line.strip()][:5000]

    def capture_path(self) -> str | None:
        """No capture: monitor mode needs sudo and would drop the user's link."""
        return None

    def reset(self) -> None:
        type(self)._shared_cache_at.pop(self.interface, None)

    def close(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"<MacOSDUT {self.interface}>"


def _main() -> int:
    """Manual probe: `python -m airframe.dut.macos`."""
    dut = MacOSDUT()
    print("identity  :", dut.identity())
    print("caps      :", sorted(c.value for c in dut.capabilities))
    print("ssid      :", dut.ssid())
    print("state     :", dut.state().value)
    print("gateway   :", dut.gateway())
    print("stats     :", dut.stats())
    print("quality   :", dut.stats().link_quality)
    print("connect   :", dut.connect().describe())
    for s in dut.scan():
        print("observed  :", s)
    print("missing caps (tests will skip):",
          sorted(c.value for c in Capability if c not in dut.capabilities))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
