"""Fixtures for the flake demonstration.

Kept in `demo/` rather than `tests/` deliberately: this directory contains a test
that is *supposed* to be flaky, and a genuinely flaky test living in the real suite
would be exactly the problem the suite exists to detect. `testpaths` in
pyproject.toml points at `tests/` only, so this is never collected by accident.

Run it with: make test-flaky
"""

import pytest

pytest_plugins = ["tests.plugin"]


@pytest.fixture(scope="session")
def backend_name(pytestconfig):
    return str(pytestconfig.getoption("--dut"))


@pytest.fixture(scope="session")
def seed(pytestconfig):
    return int(pytestconfig.getoption("--seed"))
