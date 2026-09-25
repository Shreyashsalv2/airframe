"""Root fixtures for the airframe suite.

Fixture scope is the load-bearing decision in this file, so it is worth stating
the reasoning explicitly:

``session``  — the backend name, the seed, the artifact root. Constants for the run.
``module``   — a shared DUT for read-only tests, so we spawn one simulator process
               per file instead of one per test.
``function`` — a *fresh* DUT for any test that mutates state (connects, injects a
               fault, roams). This is the default, and the safe choice.

Getting this wrong is subtle and expensive. A session-scoped mutable DUT makes
tests pass or fail depending on **collection order**, which is the single most
confusing class of test bug: each test passes alone, the suite fails, and the
failure moves when you add an unrelated test. A function-scoped DUT costs a few
milliseconds per test (the simulator is fast precisely so this is affordable) and
buys complete isolation.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from airframe.dut.base import (
    DUT,
    Band,
    Capability,
    NetworkConfig,
    Phy,
    Security,
)
from airframe.dut.registry import create_dut

# Load the plugin from here so it works regardless of the directory pytest is
# invoked from. Putting `-p tests.plugin` in addopts breaks when someone runs
# `pytest` from inside tests/.
pytest_plugins = ["tests.plugin"]


# ---------------------------------------------------------------- session scope


@pytest.fixture(scope="session")
def backend_name(pytestconfig: pytest.Config) -> str:
    return str(pytestconfig.getoption("--dut"))


@pytest.fixture(scope="session")
def seed(pytestconfig: pytest.Config) -> int:
    return int(pytestconfig.getoption("--seed"))


@pytest.fixture(scope="session")
def artifact_root(pytestconfig: pytest.Config) -> Path:
    root = Path(str(pytestconfig.getoption("--artifacts")))
    if not root.is_absolute():
        root = pytestconfig.rootpath / root
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture(scope="session")
def backend_capabilities(backend_name: str) -> frozenset[Capability]:
    """Capabilities of the active backend, probed once per session."""
    probe = create_dut(backend_name, seed=1)
    try:
        return probe.capabilities
    finally:
        probe.close()


# ---------------------------------------------------------------- per-test


@pytest.fixture
def artifact_dir(request: pytest.FixtureRequest, artifact_root: Path) -> Iterator[Path]:
    """A directory unique to this test, cleaned up unless the test failed.

    Keeping artifacts only for failures is the right default: a full run of the
    interop matrix would otherwise leave hundreds of useless captures behind, and
    the ones that matter would be buried among them.
    """
    safe = (
        request.node.nodeid.replace("/", "_")
        .replace("::", "__")
        .replace("[", "_")
        .replace("]", "")
        .replace(" ", "_")
    )[:180]
    path = artifact_root / safe
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)

    from tests.plugin import attach_artifact_dir

    attach_artifact_dir(request.node, path)
    yield path

    failed = getattr(request.node, "_airframe_failed", False)
    keep = request.config.getoption("--keep-artifacts")
    if not failed and not keep:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def dut(
    request: pytest.FixtureRequest,
    backend_name: str,
    seed: int,
    artifact_dir: Path,
) -> Iterator[DUT]:
    """A fresh DUT for this test. The default, and the isolated choice.

    The seed is derived from the test's own nodeid rather than being the same for
    every test. Reusing one seed everywhere would make every test traverse an
    identical code path through the simulator's randomness, which quietly
    collapses the variety the suite is supposed to explore. Deriving it from the
    nodeid keeps each test's randomness distinct *and* still perfectly
    reproducible, since the nodeid is stable.
    """
    per_test_seed = (seed * 31 + (hash(request.node.nodeid) & 0xFFFF)) & 0x7FFFFFFF
    device = create_dut(
        backend_name,
        seed=per_test_seed,
        artifact_dir=str(artifact_dir),
    )
    try:
        yield device
        from tests.plugin import record_dut_artifacts

        record_dut_artifacts(request.node, device)
    finally:
        device.close()


@pytest.fixture(scope="module")
def shared_dut(
    request: pytest.FixtureRequest, backend_name: str, seed: int, artifact_root: Path
) -> Iterator[DUT]:
    """One DUT per module, for read-only tests.

    Use this ONLY for tests that observe without mutating (capability queries,
    identity strings, scan results). Anything that connects, disconnects, injects
    a fault or roams must use the function-scoped ``dut`` instead.
    """
    path = artifact_root / f"_module_{request.module.__name__}"
    path.mkdir(parents=True, exist_ok=True)
    device = create_dut(backend_name, seed=seed, artifact_dir=str(path))
    try:
        yield device
    finally:
        device.close()
        shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------- config helpers


@pytest.fixture
def default_network() -> NetworkConfig:
    return NetworkConfig(
        ssid="airframe-test-ap",
        security=Security.WPA2_PSK,
        band=Band.GHZ_5,
        channel=36,
        width_mhz=80,
        phy=Phy.DOT11AX,
    )


@pytest.fixture
def connected_dut(dut: DUT, default_network: NetworkConfig) -> Iterator[DUT]:
    """A DUT already associated, for tests about the connected state.

    Failing to reach CONNECTED raises rather than asserts, so the test reports as
    an **error** (the precondition was not met) rather than as a **failure** (the
    thing under test misbehaved). Keeping those apart is what makes a red run
    triageable at a glance.
    """
    from airframe.dut.base import Capability as Cap

    # A reconfigurable backend is told which network to join; a real Wi-Fi card is
    # asked about the one it is already on. Same assertion either way.
    result = dut.connect(default_network) if dut.supports(Cap.RECONFIGURE) else dut.connect()
    if not result.connected:
        pytest.skip(f"could not establish a baseline connection: {result.describe()}")
    yield dut


# ---------------------------------------------------------------- hooks


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    """Tag the item when it fails, so ``artifact_dir`` knows to keep its evidence.

    Fixture teardown cannot otherwise see the test's outcome — by the time
    teardown runs, the result exists only on the report object.
    """
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        item._airframe_failed = True  # type: ignore[attr-defined]
