"""Simulator backend — drives the C++ `airframe-sim` binary over TCP.

Transport design notes, because this is where socket code usually goes wrong:

* **The port is chosen by the OS, not by us.** We pass ``--port 0``, the kernel
  picks a free port, and the child prints ``AIRFRAME_SIM_LISTENING port=NNNNN``
  on stdout. Hardcoding a port is the classic cause of "the suite passes alone
  but fails under ``-n auto``" — two workers race for the same port.

* **TCP is a byte stream, not a message stream.** One ``recv()`` can return half a
  response or three responses. The reader below accumulates into a buffer and
  splits on newlines, which is the only correct way to frame this.

* **Teardown is defensive.** ``close()`` is idempotent and escalates
  politely: ask the simulator to quit, then ``terminate()``, then ``kill()``.
  A test framework that leaks child processes will eventually exhaust the
  machine, and the failure looks like something else entirely.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from airframe.dut.base import (
    DUT,
    Band,
    Capability,
    ConnectResult,
    DUTError,
    Fault,
    LinkStats,
    NetworkConfig,
    Phy,
    ScanResult,
    Security,
    State,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
_LISTEN_RE = re.compile(r"AIRFRAME_SIM_LISTENING port=(\d+)")

DEFAULT_BINARY_CANDIDATES = (
    REPO_ROOT / "sim" / "build" / "airframe-sim",
    REPO_ROOT / "sim" / "build-asan" / "airframe-sim",
)


def find_binary(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Locate the simulator binary, with a clear error if it has not been built."""
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.exists():
            raise DUTError(f"simulator binary not found at {p}")
        return p
    env = os.environ.get("AIRFRAME_SIM_BINARY")
    if env:
        return find_binary(env)
    for candidate in DEFAULT_BINARY_CANDIDATES:
        if candidate.exists():
            return candidate
    on_path = shutil.which("airframe-sim")
    if on_path:
        return Path(on_path)
    raise DUTError(
        "airframe-sim is not built. Run:\n"
        "  cmake -S sim -B sim/build && cmake --build sim/build -j8\n"
        "or set AIRFRAME_SIM_BINARY to an existing binary."
    )


class SimDUT(DUT):
    """Deterministic simulated Wi-Fi station.

    Every capability is available, which is exactly why this backend — not the
    real hardware — is what the bulk of the suite runs against.
    """

    backend = "sim"

    def __init__(
        self,
        *,
        seed: int = 42,
        config: NetworkConfig | None = None,
        artifact_dir: str | os.PathLike[str] | None = None,
        binary: str | os.PathLike[str] | None = None,
        connect_timeout: float = 10.0,
        io_timeout: float = 30.0,
    ) -> None:
        self.seed = seed
        self.config = config or NetworkConfig()
        self.binary = find_binary(binary)
        self._io_timeout = io_timeout

        self.artifact_dir = Path(artifact_dir) if artifact_dir else None
        if self.artifact_dir:
            self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = str(self.artifact_dir / "sim.log") if self.artifact_dir else ""
        self._pcap_path = str(self.artifact_dir / "sim.pcap") if self.artifact_dir else ""

        self._proc: subprocess.Popen[str] | None = None
        self._sock: socket.socket | None = None
        self._rx = b""                      # partial-response buffer (see module docstring)
        self._stderr_lines: list[str] = []
        self._closed = False

        self._spawn(connect_timeout)
        self._open_session()

    # ---------------------------------------------------------------- transport

    def _spawn(self, timeout: float) -> None:
        self._proc = subprocess.Popen(
            [str(self.binary), "--serve", "--host", "127.0.0.1", "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        # Drain stderr on a daemon thread. Without this, a chatty child fills the
        # pipe buffer and blocks forever — a deadlock that looks like a hang.
        def drain() -> None:
            assert self._proc and self._proc.stderr
            for line in self._proc.stderr:
                self._stderr_lines.append(line.rstrip("\n"))

        threading.Thread(target=drain, daemon=True, name="sim-stderr").start()

        assert self._proc.stdout is not None
        port: int | None = None
        # Block on the child's own announcement rather than polling or sleeping:
        # a fixed sleep is either too short (flaky) or too long (slow), and there
        # is no value that is reliably both.
        for raw in self._proc.stdout:
            m = _LISTEN_RE.search(raw)
            if m:
                port = int(m.group(1))
                break
        if port is None:
            rc = self._proc.poll()
            raise DUTError(
                f"simulator exited before it started listening (rc={rc}): "
                + "; ".join(self._stderr_lines[-5:])
            )

        self.port = port
        self._sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self._sock.settimeout(self._io_timeout)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _request(self, **payload: Any) -> dict[str, Any]:
        """Send one command, read exactly one response."""
        if self._sock is None:
            raise DUTError("simulator connection is closed")

        line = (json.dumps(payload) + "\n").encode()
        try:
            self._sock.sendall(line)
        except OSError as exc:
            raise DUTError(f"failed to send {payload.get('cmd')!r}: {exc}") from exc

        while b"\n" not in self._rx:
            try:
                chunk = self._sock.recv(65536)
            except TimeoutError as exc:
                raise DUTError(
                    f"timed out after {self._io_timeout}s waiting for "
                    f"{payload.get('cmd')!r}"
                ) from exc
            if not chunk:
                rc = self._proc.poll() if self._proc else None
                raise DUTError(
                    f"simulator closed the connection during {payload.get('cmd')!r} "
                    f"(rc={rc}); stderr: {'; '.join(self._stderr_lines[-5:])}"
                )
            self._rx += chunk

        raw, self._rx = self._rx.split(b"\n", 1)
        try:
            resp: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DUTError(f"unparseable response {raw[:200]!r}: {exc}") from exc

        # An illegal transition is a bug in the caller, so it must surface loudly
        # rather than being folded into a benign-looking result.
        if resp.get("error_kind") == "illegal_transition":
            raise DUTError(f"illegal state transition: {resp.get('error')}")
        return resp

    def _open_session(self) -> None:
        payload: dict[str, Any] = {
            "cmd": "open",
            "seed": self.seed,
            **self.config.as_dict(),
        }
        payload["width"] = payload.pop("width_mhz")
        if self._log_path:
            payload["log_path"] = self._log_path
        if self._pcap_path:
            payload["pcap_path"] = self._pcap_path
        resp = self._request(**payload)
        if not resp.get("ok"):
            raise DUTError(f"failed to open sim session: {resp.get('error')}")
        self._bssid = str(resp.get("bssid", ""))

    # ---------------------------------------------------------------- DUT API

    @property
    def capabilities(self) -> frozenset[Capability]:
        return frozenset(Capability)     # the simulator can do everything

    def identity(self) -> str:
        return (
            f"sim(seed={self.seed}, {self.config.band.value}/"
            f"{self.config.security.value}/{self.config.phy.value})"
        )

    def scan(self) -> list[ScanResult]:
        resp = self._request(cmd="scan")
        out: list[ScanResult] = []
        for n in resp.get("networks", []):
            out.append(
                ScanResult(
                    ssid=n["ssid"],
                    bssid=n["bssid"],
                    band=Band(n["band"]),
                    channel=int(n["channel"]),
                    width_mhz=int(n["width_mhz"]),
                    phy=Phy(n["phy"]),
                    security=Security(n["security"]),
                    rssi_dbm=int(n["rssi_dbm"]),
                )
            )
        return out

    def connect(self, config: NetworkConfig | None = None) -> ConnectResult:
        if config is not None and config != self.config:
            # Reconfiguring means a new session: band/security/PHY are properties
            # of the radio setup, not of an individual connection attempt.
            self.config = config
            self._open_session()
        resp = self._request(cmd="connect")
        return ConnectResult.from_dict(resp.get("result", {}))

    def disconnect(self) -> None:
        if self._sock is None:
            return
        self._request(cmd="disconnect")

    def state(self) -> State:
        resp = self._request(cmd="state")
        try:
            return State(resp.get("state", "UNKNOWN"))
        except ValueError:
            return State.UNKNOWN

    def stats(self) -> LinkStats:
        resp = self._request(cmd="stats")
        return LinkStats.from_dict(resp.get("stats", {}))

    def inject_fault(self, fault: Fault, probability: float = 1.0, code: int = 0) -> None:
        resp = self._request(
            cmd="inject_fault", fault=fault.value, probability=probability, code=code
        )
        if not resp.get("ok"):
            raise DUTError(f"inject_fault failed: {resp.get('error')}")

    def roam(self) -> ConnectResult:
        resp = self._request(cmd="roam")
        return ConnectResult.from_dict(resp.get("result", {}))

    def run_traffic(self, duration_ms: int) -> bool:
        resp = self._request(cmd="run", ms=duration_ms)
        return bool(resp.get("ok"))

    def summary(self) -> dict[str, Any]:
        """Full session summary, including the transition history."""
        resp = self._request(cmd="summary")
        return dict(resp.get("summary", {}))

    def logs(self) -> list[str]:
        if not self._log_path or not Path(self._log_path).exists():
            return []
        return Path(self._log_path).read_text().splitlines()

    def capture_path(self) -> str | None:
        if self._pcap_path and Path(self._pcap_path).exists():
            return self._pcap_path
        return None

    def reset(self) -> None:
        self._request(cmd="reset")

    # ---------------------------------------------------------------- teardown

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        # Ask nicely first; a clean shutdown flushes the log and pcap files.
        if self._sock is not None:
            try:
                self._sock.sendall(b'{"cmd":"quit"}\n')
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

        if self._proc is not None:
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait(timeout=3)
            for stream in (self._proc.stdout, self._proc.stderr):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass
            self._proc = None

    def __repr__(self) -> str:
        return f"<SimDUT seed={self.seed} port={getattr(self, 'port', '?')}>"


def _main() -> int:
    """Manual smoke test: `python -m airframe.dut.sim`."""
    with SimDUT(seed=42, artifact_dir="/tmp/airframe_sim_smoke") as dut:
        print("identity :", dut.identity())
        print("caps     :", sorted(c.value for c in dut.capabilities))
        print("scan     :", len(dut.scan()), "networks")
        r = dut.connect()
        print("connect  :", r.describe())
        print("state    :", dut.state().value)
        print("stats    :", dut.stats())
        dut.run_traffic(1000)
        print("roam     :", dut.roam().describe())
        dut.disconnect()
        print("pcap     :", dut.capture_path())
        print("log lines:", len(dut.logs()))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
