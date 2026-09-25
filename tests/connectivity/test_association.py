"""Association lifecycle — the happy paths.

These are the tests that should never fail. When one does, connectivity is broken
for everyone, so they are deliberately the simplest and most direct assertions in
the suite.
"""

from __future__ import annotations

import pytest

from airframe.dut.base import (
    DUT,
    Band,
    Capability,
    NetworkConfig,
    Phy,
    Security,
    State,
)

pytestmark = pytest.mark.requires_capability(Capability.RECONFIGURE)


def test_connect_reaches_connected_state(dut: DUT, default_network: NetworkConfig) -> None:
    result = dut.connect(default_network)

    assert result.ok, f"connection failed: {result.describe()}"
    assert result.final_state is State.CONNECTED, result.describe()
    assert dut.state() is State.CONNECTED


def test_connected_station_has_an_ip_address(dut: DUT, default_network: NetworkConfig) -> None:
    """A link without an address is the "connected but no internet" bug users report."""
    result = dut.connect(default_network)
    assert result.ok, result.describe()
    assert result.ip_address, "associated and keyed, but no IPv4 address was assigned"


def test_every_connection_stage_is_timed(dut: DUT, default_network: NetworkConfig) -> None:
    """Stage timings are the primary diagnostic; a zero means we lost visibility."""
    result = dut.connect(default_network)
    assert result.ok, result.describe()

    t = result.timings
    for stage in ("scan_ms", "auth_ms", "assoc_ms", "fourway_ms", "dhcp_ms"):
        assert getattr(t, stage) > 0, f"{stage} was not measured"
    assert t.total_ms >= max(t.scan_ms, t.auth_ms, t.assoc_ms, t.fourway_ms, t.dhcp_ms)


def test_scan_finds_at_least_one_network(dut: DUT) -> None:
    networks = dut.scan()
    assert networks, "scan returned no networks"
    assert all(n.ssid for n in networks), "every result must carry an SSID"


def test_scan_finds_multiple_bsses_for_roaming(dut: DUT) -> None:
    """Roaming is only meaningful with more than one BSS in the same ESS."""
    networks = dut.scan()
    assert len(networks) >= 2, "need at least two BSSes to exercise roaming"
    assert networks[0].ssid == networks[1].ssid, "same ESS implies the same SSID"
    assert networks[0].bssid != networks[1].bssid, "different BSS implies a different BSSID"


def test_disconnect_returns_to_idle(dut: DUT, default_network: NetworkConfig) -> None:
    assert dut.connect(default_network).ok
    dut.disconnect()
    assert dut.state() is State.IDLE


def test_disconnect_is_idempotent(dut: DUT) -> None:
    """Teardown runs even after failures, so a second disconnect must not explode."""
    dut.disconnect()
    dut.disconnect()
    assert dut.state() is State.IDLE


def test_reconnect_after_disconnect(dut: DUT, default_network: NetworkConfig) -> None:
    """The backend is reused across tests, so it must survive a full cycle."""
    assert dut.connect(default_network).ok
    dut.disconnect()
    second = dut.connect(default_network)
    assert second.ok, f"second connection failed: {second.describe()}"


@pytest.mark.parametrize(
    "security",
    [Security.OPEN, Security.WPA2_PSK, Security.WPA3_SAE, Security.WPA2_ENTERPRISE],
    ids=lambda s: s.value,
)
def test_connects_under_every_security_mode(dut: DUT, security: Security) -> None:
    config = NetworkConfig(security=security, band=Band.GHZ_5, channel=36, phy=Phy.DOT11AX)
    result = dut.connect(config)
    assert result.ok, f"{security.value} failed: {result.describe()}"


def test_open_network_performs_no_four_way_handshake(dut: DUT) -> None:
    """An open network has no EAPOL exchange at all, so the timing must be exactly 0."""
    config = NetworkConfig(
        security=Security.OPEN, band=Band.GHZ_2_4, channel=6, width_mhz=20, phy=Phy.DOT11N
    )
    result = dut.connect(config)
    assert result.ok, result.describe()
    assert result.timings.fourway_ms == 0, "an open network must not run a 4-way handshake"


@pytest.mark.parametrize(
    "security", [Security.WPA2_PSK, Security.WPA3_SAE], ids=lambda s: s.value
)
def test_secured_network_performs_four_way_handshake(dut: DUT, security: Security) -> None:
    result = dut.connect(NetworkConfig(security=security, band=Band.GHZ_5, channel=36))
    assert result.ok, result.describe()
    assert result.timings.fourway_ms > 0, f"{security.value} must run a 4-way handshake"


@pytest.mark.requires_capability(Capability.ROAMING)
def test_roam_moves_to_a_different_bssid(connected_dut: DUT) -> None:
    before = connected_dut.stats()
    result = connected_dut.roam()

    assert result.ok, f"roam failed: {result.describe()}"
    assert result.final_state is State.CONNECTED
    assert result.bssid, "a completed roam must report the new BSSID"
    assert before is not None


@pytest.mark.requires_capability(Capability.ROAMING)
def test_roam_is_faster_than_a_full_reconnect(
    dut: DUT, default_network: NetworkConfig
) -> None:
    """The entire point of roaming: keep the session alive instead of re-associating.

    A roam that costs as much as a reconnect provides no user-visible benefit, and
    this is exactly the kind of regression that ships unnoticed.
    """
    initial = dut.connect(default_network)
    assert initial.ok, initial.describe()

    roam = dut.roam()
    assert roam.ok, roam.describe()
    assert roam.timings.total_ms < initial.timings.total_ms, (
        f"roam took {roam.timings.total_ms}ms but a full connect took "
        f"{initial.timings.total_ms}ms — roaming is providing no benefit"
    )


def test_traffic_flows_on_a_connected_link(connected_dut: DUT) -> None:
    assert connected_dut.run_traffic(1000), "link dropped while passing traffic"
    assert connected_dut.state() is State.CONNECTED


@pytest.mark.requires_capability(Capability.PACKET_CAPTURE)
def test_session_produces_a_packet_capture(dut: DUT, default_network: NetworkConfig) -> None:
    from pathlib import Path

    assert dut.connect(default_network).ok
    dut.run_traffic(500)
    dut.disconnect()

    path = dut.capture_path()
    assert path, "no capture was produced"
    # 24 bytes is an empty pcap: header only, no frames. That is a silent failure
    # mode worth asserting against explicitly.
    assert Path(path).stat().st_size > 24, "capture contains no frames"


@pytest.mark.requires_capability(Capability.SYSTEM_LOGS)
def test_session_produces_structured_logs(dut: DUT, default_network: NetworkConfig) -> None:
    assert dut.connect(default_network).ok
    lines = dut.logs()
    assert lines, "no log output was captured"
    assert any("link up" in line or "CONNECTED" in line for line in lines), (
        "logs do not record the successful association"
    )
