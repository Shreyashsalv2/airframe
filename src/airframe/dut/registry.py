"""Backend registry — one place that knows how to construct a DUT.

Kept tiny and separate so that adding a backend (a router over SSH, an Android
phone over ADB, a second simulator build) touches exactly one function. The
pytest fixtures never import a concrete backend class directly; they ask here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from airframe.dut.base import DUT, DUTError, NetworkConfig

BackendFactory = Callable[..., DUT]

_BACKENDS: dict[str, str] = {
    "sim": "airframe.dut.sim:SimDUT",
    "macos": "airframe.dut.macos:MacOSDUT",
    "replay": "airframe.dut.replay:ReplayDUT",
}


def available_backends() -> list[str]:
    return sorted(_BACKENDS)


def _load(spec: str) -> type[DUT]:
    module_name, _, class_name = spec.partition(":")
    import importlib

    module = importlib.import_module(module_name)
    return getattr(module, class_name)  # type: ignore[no-any-return]


def create_dut(
    backend: str,
    *,
    seed: int = 42,
    config: NetworkConfig | None = None,
    artifact_dir: str | None = None,
    **kwargs: Any,
) -> DUT:
    """Construct a backend by name.

    Backends take genuinely different arguments — a seed means nothing to real
    hardware — so this filters rather than forcing a uniform constructor. A
    uniform constructor that ignores half its arguments is a worse lie than an
    honest asymmetry.
    """
    if backend not in _BACKENDS:
        raise DUTError(
            f"unknown backend {backend!r}; available: {', '.join(available_backends())}"
        )

    cls = _load(_BACKENDS[backend])
    if backend == "sim":
        return cls(seed=seed, config=config, artifact_dir=artifact_dir, **kwargs)
    return cls(artifact_dir=artifact_dir, **kwargs)


def register_backend(name: str, spec: str) -> None:
    """Register an additional backend, e.g. ``"ssh_router"`` -> ``"pkg.mod:Class"``.

    This exists so the Day-1 lab ("add a third backend") is a genuine exercise in
    extending the abstraction rather than editing a hardcoded if/else.
    """
    _BACKENDS[name] = spec
