"""Replay backend — a third DUT, written to test the abstraction's central claim.

The architecture promises that adding a backend costs one file. This is that file.

Instead of running a simulator or reading real hardware, it replays a session that was
already recorded in `data/corpus_manifest.json`. The practical use is re-examining a
past failure without spinning anything up — the artifacts are already on disk.

Its capability set is deliberately narrow, which is the point: a recording cannot be
told to fail differently than it did, so it does NOT advertise FAULT_INJECTION. Tests
that need that skip with a stated reason, exactly as they do for real hardware.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from airframe.dut.base import (
    Band,
    Capability,
    ConnectResult,
    DUT,
    DUTError,
    LinkStats,
    NetworkConfig,
    Phy,
    ScanResult,
    Security,
    State,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST = REPO_ROOT / "data" / "corpus_manifest.json"


class ReplayDUT(DUT):
    """Replays a recorded session. Read-only by nature."""

    backend = "replay"

    def __init__(self, *, tag: str | None = None, artifact_dir: str | None = None,
                 **_ignored: Any) -> None:
        if not MANIFEST.exists():
            raise DUTError(f"no corpus at {MANIFEST}; run scripts/build_corpus.py")
        entries = json.loads(MANIFEST.read_text())["deterministic"]
        if not entries:
            raise DUTError("corpus manifest is empty")

        self._entry = (
            next((e for e in entries if e["tag"] == tag), None) if tag
            else next((e for e in entries if e["fault"] == "NONE"), entries[0])
        )
        if self._entry is None:
            raise DUTError(f"no recorded session tagged {tag!r}")

        self._summary = self._entry["summary"]
        self._state = State.IDLE
        self.artifact_dir = artifact_dir

    # ---- what a recording can and cannot do ----

    @property
    def capabilities(self) -> frozenset[Capability]:
        # A recording cannot be reconfigured or ordered to fail differently — it
        # already happened. It IS deterministic (replaying gives the same answer)
        # and it does carry a capture and logs.
        return frozenset({
            Capability.DETERMINISTIC,
            Capability.PACKET_CAPTURE,
            Capability.SYSTEM_LOGS,
        })

    def identity(self) -> str:
        return f"replay({self._entry['tag']})"

    # ---- the same five methods every backend implements ----

    def scan(self) -> list[ScanResult]:
        return [ScanResult(
            ssid=self._summary["ssid"],
            bssid=self._summary["bssid"],
            band=Band(self._summary["band"]),
            channel=int(self._summary["channel"]),
            width_mhz=int(self._summary["width_mhz"]),
            phy=Phy(self._summary["phy"]),
            security=Security(self._summary["security"]),
            rssi_dbm=int(self._summary["stats"]["rssi_dbm"]),
        )]

    def connect(self, config: NetworkConfig | None = None) -> ConnectResult:
        if config is not None:
            raise DUTError(
                "replay backend cannot be reconfigured; it replays what was recorded"
            )
        result = ConnectResult.from_dict(self._summary["result"])
        self._state = result.final_state
        return result

    def disconnect(self) -> None:
        self._state = State.IDLE

    def state(self) -> State:
        return self._state

    def stats(self) -> LinkStats:
        return LinkStats.from_dict(self._summary["stats"])

    # ---- artifacts already exist on disk ----

    def logs(self) -> list[str]:
        path = Path(self._entry["log"])
        return path.read_text(errors="replace").splitlines() if path.exists() else []

    def capture_path(self) -> str | None:
        path = Path(self._entry["pcap"])
        return str(path) if path.exists() else None

    def run_traffic(self, duration_ms: int) -> bool:
        """A recording has no live link, so report whether the RECORDED session was up.

        Implemented after the first run against the real suite reported
        NotImplementedError — a genuine gap in this backend rather than a leak in the
        abstraction.
        """
        return self._state is State.CONNECTED

    def close(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"<ReplayDUT {self._entry['tag']}>"
