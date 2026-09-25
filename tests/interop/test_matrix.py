"""The interoperability matrix — combinatorial coverage across radio configurations.

This is where a test *framework* earns its keep over a pile of test *functions*.
The matrix below expands into well over a hundred cases from a couple of dozen
lines, and every case gets a readable ID so a failure reads like a bug title:

    test_connects_across_matrix[5GHz-80-wpa3_sae-11ax]        PASSED
    test_connects_across_matrix[6GHz-160-wpa2_psk-11ax]       SKIPPED (invalid combo)

Two ideas do the work here.

**Only valid combinations are generated.** 802.11 forbids plenty of pairings:
802.11ac is 5 GHz only, 802.11n has no 6 GHz, 6 GHz mandates WPA3 and outlaws Open
and WPA2-PSK, and channel width is band-dependent. Rather than generating the full
cross product and letting two thirds of it fail, the domain rules are encoded in
``is_valid_combination`` and the invalid cases are tested *separately*, as negative
tests that assert the DUT refuses them for the right reason. Expected failures
belong in their own tests, not mixed in as noise.

**The matrix is pruned deliberately.** The full cross product of band × width ×
security × PHY × channel is thousands of cases, most of which exercise identical
code paths. What ships is a representative sample plus targeted coverage of the
combinations that historically break. Knowing that exhaustive is not the same as
effective — and being able to say *why* you pruned — is the real skill.
"""

from __future__ import annotations

import itertools

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

# ---------------------------------------------------------------- domain rules

CHANNELS: dict[Band, list[int]] = {
    Band.GHZ_2_4: [1, 6, 11],           # the three non-overlapping channels
    Band.GHZ_5: [36, 44, 100, 149],     # UNII-1, UNII-2, DFS, UNII-3
    Band.GHZ_6: [1, 37, 117],           # low / mid / high 6 GHz
}

WIDTHS: dict[Band, list[int]] = {
    Band.GHZ_2_4: [20, 40],
    Band.GHZ_5: [20, 40, 80, 160],
    Band.GHZ_6: [20, 80, 160, 320],     # 320 MHz is 802.11be only
}


def is_valid_combination(band: Band, width: int, security: Security, phy: Phy) -> tuple[bool, str]:
    """Encode the real 802.11 rules. Returns (valid, reason-if-not)."""
    if width not in WIDTHS[band]:
        return False, f"{width}MHz is not available on {band.value}"
    if phy is Phy.DOT11AC and band is not Band.GHZ_5:
        return False, "802.11ac (VHT) is 5GHz only"
    if phy is Phy.DOT11N and band is Band.GHZ_6:
        return False, "802.11n (HT) has no 6GHz operation"
    if phy is Phy.DOT11N and width > 40:
        return False, "802.11n supports at most 40MHz"
    if phy is Phy.DOT11AC and width > 160:
        return False, "802.11ac supports at most 160MHz"
    if width == 320 and phy is not Phy.DOT11BE:
        return False, "320MHz requires 802.11be"
    if band is Band.GHZ_6 and security in (Security.OPEN, Security.WPA2_PSK):
        return False, f"6GHz mandates WPA3; {security.value} is forbidden"
    return True, ""


def _matrix() -> list[NetworkConfig]:
    """Representative valid configurations across the whole radio space."""
    out: list[NetworkConfig] = []
    for band, security, phy in itertools.product(Band, Security, Phy):
        for width in WIDTHS[band]:
            valid, _ = is_valid_combination(band, width, security, phy)
            if not valid:
                continue
            # One channel per (band, width, security, phy) keeps the matrix at a
            # useful size; channel coverage is exercised separately below.
            out.append(
                NetworkConfig(
                    security=security,
                    band=band,
                    channel=CHANNELS[band][0],
                    width_mhz=width,
                    phy=phy,
                )
            )
    return out


def _invalid_matrix() -> list[tuple[Band, int, Security, Phy, str]]:
    """Combinations the spec forbids, with the reason they are forbidden."""
    out = []
    for band, security, phy in itertools.product(Band, Security, Phy):
        for width in (20, 40, 80, 160, 320):
            valid, reason = is_valid_combination(band, width, security, phy)
            if not valid and width in WIDTHS[band]:
                out.append((band, width, security, phy, reason))
    return out


VALID_MATRIX = _matrix()
INVALID_MATRIX = _invalid_matrix()


# ---------------------------------------------------------------- positive tests


@pytest.mark.parametrize("config", VALID_MATRIX, ids=lambda c: c.test_id())
def test_connects_across_matrix(dut: DUT, config: NetworkConfig) -> None:
    """Every spec-valid radio configuration must associate successfully."""
    result = dut.connect(config)
    assert result.ok, f"{config.test_id()} failed: {result.describe()}"
    assert result.final_state is State.CONNECTED


@pytest.mark.parametrize(
    "band,channel",
    [(b, c) for b in Band for c in CHANNELS[b]],
    ids=lambda v: str(v),
)
def test_connects_on_every_channel(dut: DUT, band: Band, channel: int) -> None:
    """Channel coverage, including DFS channels and the 6 GHz range."""
    security = Security.WPA3_SAE if band is Band.GHZ_6 else Security.WPA2_PSK
    config = NetworkConfig(
        security=security, band=band, channel=channel, width_mhz=20, phy=Phy.DOT11AX
    )
    result = dut.connect(config)
    assert result.ok, f"{band.value} ch{channel} failed: {result.describe()}"


@pytest.mark.parametrize("width", [20, 40, 80, 160], ids=lambda w: f"{w}MHz")
def test_wider_channels_negotiate_higher_rates(dut: DUT, width: int) -> None:
    """Width must actually buy throughput, otherwise why configure it."""
    config = NetworkConfig(
        security=Security.WPA2_PSK, band=Band.GHZ_5, channel=36, width_mhz=width,
        phy=Phy.DOT11AX,
    )
    assert dut.connect(config).ok
    stats = dut.stats()
    assert stats.width_mhz == width, f"negotiated {stats.width_mhz}MHz, asked for {width}MHz"
    assert stats.tx_rate_mbps > 0


def test_rate_increases_monotonically_with_width(dut: DUT) -> None:
    """A property test over the whole width range, rather than four point checks.

    Point assertions can all pass while the *relationship* is broken. Checking the
    ordering catches a rate model that is subtly wrong in the middle.
    """
    rates = {}
    for width in (20, 40, 80, 160):
        config = NetworkConfig(
            security=Security.WPA2_PSK, band=Band.GHZ_5, channel=36,
            width_mhz=width, phy=Phy.DOT11AX,
        )
        assert dut.connect(config).ok
        rates[width] = dut.stats().tx_rate_mbps
        dut.disconnect()

    ordered = [rates[w] for w in (20, 40, 80, 160)]
    assert ordered == sorted(ordered), f"rate is not monotonic in channel width: {rates}"


@pytest.mark.parametrize("phy", list(Phy), ids=lambda p: p.value)
def test_every_phy_generation_connects_on_a_compatible_band(dut: DUT, phy: Phy) -> None:
    band = Band.GHZ_2_4 if phy is Phy.DOT11N else Band.GHZ_5
    width = 20 if phy is Phy.DOT11N else 80
    config = NetworkConfig(
        security=Security.WPA2_PSK, band=band, channel=CHANNELS[band][0],
        width_mhz=width, phy=phy,
    )
    result = dut.connect(config)
    assert result.ok, f"{phy.value} on {band.value} failed: {result.describe()}"


# ---------------------------------------------------------------- negative tests


@pytest.mark.parametrize(
    "band,width,security,phy,reason",
    INVALID_MATRIX,
    ids=lambda v: str(getattr(v, "value", v)),
)
def test_invalid_combinations_are_refused(
    dut: DUT, band: Band, width: int, security: Security, phy: Phy, reason: str
) -> None:
    """Spec-invalid configurations must be refused, and refused *correctly*.

    A DUT that happily "connects" using WPA2 on 6 GHz is a worse bug than one that
    fails to connect at all, because it means the radio is doing something the
    spec forbids and nobody noticed.
    """
    config = NetworkConfig(
        security=security, band=band, channel=CHANNELS[band][0], width_mhz=width, phy=phy
    )
    result = dut.connect(config)
    assert not result.ok, (
        f"{config.test_id()} should have been refused ({reason}) but connected"
    )
    assert result.final_state is State.FAILED
    # Must fail before transmitting: the DUT should know this is impossible.
    assert result.timings.auth_ms == 0, "an impossible config must fail before authentication"


def test_six_ghz_mandates_wpa3(dut: DUT) -> None:
    """Explicit, named test for the rule most likely to be asked about."""
    for forbidden in (Security.OPEN, Security.WPA2_PSK):
        config = NetworkConfig(
            security=forbidden, band=Band.GHZ_6, channel=37, width_mhz=80, phy=Phy.DOT11AX
        )
        result = dut.connect(config)
        assert not result.ok, f"6GHz must reject {forbidden.value}"
        dut.reset()

    allowed = NetworkConfig(
        security=Security.WPA3_SAE, band=Band.GHZ_6, channel=37, width_mhz=80, phy=Phy.DOT11AX
    )
    assert dut.connect(allowed).ok, "6GHz must accept WPA3-SAE"


def test_matrix_is_a_sensible_size() -> None:
    """Guard on the matrix itself.

    If a future edit accidentally makes this generate thousands of cases, the
    suite becomes too slow to run and people stop running it — a failure mode
    that has killed more test suites than any bug.
    """
    assert 40 <= len(VALID_MATRIX) <= 400, (
        f"matrix has {len(VALID_MATRIX)} cases; too small loses coverage, "
        "too large loses adoption"
    )
    assert INVALID_MATRIX, "negative coverage disappeared"
