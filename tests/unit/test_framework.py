"""Tests of the test framework itself — no DUT required.

Infrastructure needs tests as much as the code it tests. A bug in `ConnectResult`
parsing or in the capability gate produces *wrong test results*, which is strictly
worse than a bug in a feature: it silently changes what every other test means.
"""

from __future__ import annotations

import pytest

from airframe.dut.base import (
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
    StageTimings,
    State,
    UnsupportedOperation,
)
from airframe.dut.registry import available_backends, create_dut, register_backend

# ---------------------------------------------------------------- data shapes


class TestStageTimings:
    def test_slowest_stage_identifies_the_bottleneck(self) -> None:
        t = StageTimings(scan_ms=100, auth_ms=20, assoc_ms=30, fourway_ms=50, dhcp_ms=4000)
        assert t.slowest_stage == "dhcp"

    def test_slowest_stage_with_all_zeros_does_not_crash(self) -> None:
        assert StageTimings().slowest_stage in {"scan", "auth", "assoc", "fourway", "dhcp"}

    def test_from_dict_ignores_unknown_keys(self) -> None:
        """Forward compatibility: a newer simulator may add fields we do not know."""
        t = StageTimings.from_dict({"scan_ms": 5, "total_ms": 9})
        assert t.scan_ms == 5
        assert t.total_ms == 9
        assert t.auth_ms == 0

    def test_is_immutable(self) -> None:
        """Frozen so a test cannot accidentally mutate another test's evidence."""
        t = StageTimings(scan_ms=1)
        with pytest.raises((AttributeError, TypeError)):
            t.scan_ms = 2  # type: ignore[misc]


class TestConnectResult:
    def test_connected_requires_both_ok_and_the_connected_state(self) -> None:
        assert ConnectResult(ok=True, final_state=State.CONNECTED).connected
        # ok=True with a non-CONNECTED state would be an internal inconsistency;
        # `connected` must not paper over it.
        assert not ConnectResult(ok=True, final_state=State.DHCP).connected
        assert not ConnectResult(ok=False, final_state=State.CONNECTED).connected

    def test_describe_is_useful_on_success(self) -> None:
        r = ConnectResult(
            ok=True,
            final_state=State.CONNECTED,
            bssid="02:11:22:33:44:55",
            ip_address="192.168.1.50",
            timings=StageTimings(total_ms=1640),
        )
        text = r.describe()
        assert "02:11:22:33:44:55" in text
        assert "1640ms" in text
        assert "192.168.1.50" in text

    def test_describe_names_the_stage_and_code_on_failure(self) -> None:
        r = ConnectResult(
            ok=False,
            failed_at=State.FOURWAY,
            reason_code=15,
            reason_name="FOURWAY_HANDSHAKE_TIMEOUT",
            message="M3 never arrived",
        )
        text = r.describe()
        assert "FOURWAY_HANDSHAKE" in text
        assert "FOURWAY_HANDSHAKE_TIMEOUT" in text
        assert "M3 never arrived" in text

    def test_from_dict_round_trips_the_wire_format(self) -> None:
        payload = {
            "ok": False,
            "final_state": "FAILED",
            "fault": "DHCP_NAK",
            "status_code": 0,
            "status_name": "SUCCESS",
            "reason_code": 1,
            "reason_name": "UNSPECIFIED",
            "failed_at": "DHCP",
            "message": "no address",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ip_address": "",
            "timings": {"scan_ms": 1, "dhcp_ms": 8000, "total_ms": 8500},
        }
        r = ConnectResult.from_dict(payload)
        assert r.fault is Fault.DHCP_NAK
        assert r.failed_at is State.DHCP
        assert r.timings.dhcp_ms == 8000
        assert not r.ok

    def test_from_dict_tolerates_unknown_enum_values(self) -> None:
        """A newer simulator adding a fault must not crash an older client.

        Failing closed here would mean a single unrecognised string takes down the
        entire result-parsing path, turning a minor version skew into a total
        outage of the test rig.
        """
        r = ConnectResult.from_dict({"ok": False, "fault": "FUTURE_FAULT_9000"})
        assert r.fault is Fault.NONE

    def test_from_dict_handles_a_completely_empty_payload(self) -> None:
        r = ConnectResult.from_dict({})
        assert not r.ok
        assert r.final_state is State.UNKNOWN


class TestLinkStats:
    @pytest.mark.parametrize(
        "snr,expected",
        [(50, "excellent"), (40, "excellent"), (39, "good"), (25, "good"),
         (24, "fair"), (15, "fair"), (14, "poor"), (0, "poor"), (-5, "poor")],
    )
    def test_link_quality_boundaries(self, snr: int, expected: str) -> None:
        """Boundary values exactly, because off-by-one on a threshold is the bug."""
        assert LinkStats(snr_db=snr).link_quality == expected

    def test_from_dict_ignores_extra_fields(self) -> None:
        s = LinkStats.from_dict({"rssi_dbm": -50, "unknown_future_field": 1})
        assert s.rssi_dbm == -50


class TestNetworkConfig:
    def test_test_id_is_stable_and_readable(self) -> None:
        c = NetworkConfig(
            band=Band.GHZ_6, width_mhz=160, security=Security.WPA3_SAE, phy=Phy.DOT11AX
        )
        assert c.test_id() == "6GHz-160-wpa3_sae-11ax"

    def test_as_dict_serialises_enums_to_wire_strings(self) -> None:
        d = NetworkConfig(band=Band.GHZ_5, security=Security.WPA2_PSK).as_dict()
        assert d["band"] == "5GHz"
        assert d["security"] == "wpa2_psk"
        assert isinstance(d["channel"], int)

    def test_equality_is_by_value(self) -> None:
        """The sim backend reopens a session only when the config actually changes."""
        assert NetworkConfig(channel=36) == NetworkConfig(channel=36)
        assert NetworkConfig(channel=36) != NetworkConfig(channel=44)


class TestScanResult:
    @pytest.mark.parametrize(
        "rssi,usable", [(-30, True), (-79, True), (-80, False), (-95, False)]
    )
    def test_usability_threshold(self, rssi: int, usable: bool) -> None:
        assert ScanResult(ssid="x", bssid="y", rssi_dbm=rssi).is_usable is usable


# ---------------------------------------------------------------- registry


class TestRegistry:
    def test_both_backends_are_registered(self) -> None:
        assert set(available_backends()) >= {"sim", "macos"}

    def test_unknown_backend_raises_a_helpful_error(self) -> None:
        with pytest.raises(DUTError) as exc:
            create_dut("does_not_exist")
        # The message must list what IS available; "unknown backend" alone forces
        # the reader to go and read the source.
        assert "sim" in str(exc.value)

    def test_a_third_backend_can_be_registered(self) -> None:
        """The extension point the Day-1 lab exercises."""
        register_backend("lab_backend", "airframe.dut.sim:SimDUT")
        assert "lab_backend" in available_backends()


# ---------------------------------------------------------------- capabilities


class TestCapabilityGate:
    def test_supports_handles_enums_strings_and_garbage(self) -> None:
        dut = create_dut("sim", seed=1)
        try:
            assert dut.supports(Capability.FAULT_INJECTION)
            assert dut.supports("fault_injection")
            assert not dut.supports("teleportation")
        finally:
            dut.close()

    def test_require_raises_unsupported_operation_naming_the_backend(self) -> None:
        from airframe.dut.base import DUT as BaseDUT

        class Limited(BaseDUT):
            backend = "limited"

            @property
            def capabilities(self):  # type: ignore[override]
                return frozenset({Capability.REAL_TRAFFIC})

            def identity(self) -> str:
                return "limited"

            def scan(self):  # type: ignore[override]
                return []

            def connect(self, config=None):  # type: ignore[override]
                return ConnectResult(ok=False)

            def disconnect(self) -> None:
                return None

            def state(self):  # type: ignore[override]
                return State.IDLE

            def stats(self):  # type: ignore[override]
                return LinkStats()

        dut = Limited()
        with pytest.raises(UnsupportedOperation) as exc:
            dut.require(Capability.FAULT_INJECTION)
        assert "limited" in str(exc.value)
        assert "fault_injection" in str(exc.value)

    def test_abstract_dut_cannot_be_instantiated(self) -> None:
        """The ABC must actually enforce its contract."""
        from airframe.dut.base import DUT as BaseDUT

        with pytest.raises(TypeError):
            BaseDUT()  # type: ignore[abstract]


# ---------------------------------------------------------------- store


class TestResultStore:
    def test_retries_are_recorded_not_overwritten(self, tmp_path) -> None:
        """The central design decision of the schema, asserted directly."""
        from airframe.store import db

        conn = db.connect(tmp_path / "t.db")
        try:
            rid = db.start_run(conn, dut_backend="sim", seed=1)
            db.record_result(conn, run_id=rid, nodeid="t::a", outcome="failed", attempt=1)
            db.record_result(conn, run_id=rid, nodeid="t::a", outcome="failed", attempt=2)
            db.record_result(conn, run_id=rid, nodeid="t::a", outcome="passed", attempt=3)

            total = conn.execute("SELECT COUNT(*) c FROM results").fetchone()["c"]
            assert total == 3, "every attempt must survive"

            final = conn.execute("SELECT * FROM v_final_results").fetchone()
            assert final["outcome"] == "passed"
            assert final["attempt"] == 3
        finally:
            conn.close()

    def test_mark_flake_flags_every_attempt(self, tmp_path) -> None:
        from airframe.store import db

        conn = db.connect(tmp_path / "t.db")
        try:
            rid = db.start_run(conn, dut_backend="sim")
            db.record_result(conn, run_id=rid, nodeid="t::a", outcome="failed", attempt=1)
            db.record_result(conn, run_id=rid, nodeid="t::a", outcome="passed", attempt=2)
            db.mark_flake(conn, rid, "t::a")

            flagged = conn.execute("SELECT COUNT(*) c FROM results WHERE is_flake=1").fetchone()
            assert flagged["c"] == 2, "a flake marks the whole history, not just the pass"
        finally:
            conn.close()

    def test_foreign_keys_cascade(self, tmp_path) -> None:
        """PRAGMA foreign_keys is per-connection; this proves connect() sets it."""
        from airframe.store import db

        conn = db.connect(tmp_path / "t.db")
        try:
            rid = db.start_run(conn, dut_backend="sim")
            r = db.record_result(conn, run_id=rid, nodeid="t::a", outcome="failed")
            db.record_triage(conn, result_id=r, provider="mock", root_cause="x")
            conn.execute("DELETE FROM runs WHERE id = ?", (rid,))

            for table in ("results", "triage_reports"):
                left = conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
                assert left == 0, f"{table} was not cascaded"
        finally:
            conn.close()

    def test_schema_is_idempotent(self, tmp_path) -> None:
        """Applying the schema twice must not fail — connect() may re-run it."""
        from airframe.store import db

        conn = db.connect(tmp_path / "t.db")
        try:
            db.init_schema(conn)
            db.init_schema(conn)
        finally:
            conn.close()
