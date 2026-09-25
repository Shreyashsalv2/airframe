"""KPI measurement runner — ties probes, the store, and regression detection together.

    python -m airframe.kpi.runner              # full run against all endpoints
    python -m airframe.kpi.runner --quick      # fast subset
    python -m airframe.kpi.runner --baseline   # rebuild baselines from history
"""

from __future__ import annotations

import argparse
import sys

from airframe.dut.base import Band
from airframe.kpi.endpoints import QUICK_SET, resolve_gateway
from airframe.kpi.probes import ProbeResult, probe_all
from airframe.kpi.regression import (
    Verdict,
    detect_regressions,
    rebuild_baselines,
)
from airframe.kpi.stats import classify_mos, mos_estimate, summarise
from airframe.store import db as store


def network_context() -> tuple[str, str, str | None]:
    """Identify the network being measured: (network, band, gateway).

    Every sample is labelled with this, because a latency number without knowing
    which network and band produced it cannot be compared to anything.
    """
    try:
        from airframe.dut.macos import MacOSDUT

        dut = MacOSDUT()
        stats = dut.stats()
        scan = dut.scan()
        band = scan[0].band.value if scan else Band.GHZ_5.value
        # The SSID is redacted by macOS without Location permission, so fall back to
        # a stable synthetic label derived from observable facts. Using "<redacted>"
        # as the key would merge every network you ever measure into one baseline.
        ssid = dut.ssid()
        if ssid in ("<redacted>", "not-associated", ""):
            ssid = f"net-ch{stats.channel}-{band}"
        return ssid, band, dut.gateway()
    except Exception:
        return "unknown", "unknown", None


def run_measurements(
    *, quick: bool = False, store_results: bool = True, verbose: bool = True
) -> tuple[int | None, list[ProbeResult]]:
    network, band, gateway = network_context()
    endpoints = resolve_gateway(gateway)
    if quick:
        endpoints = [e for e in endpoints if e.name in QUICK_SET]

    if verbose:
        print(f"network : {network}")
        print(f"band    : {band}")
        print(f"gateway : {gateway or 'not found'}")
        print(f"probing : {len(endpoints)} endpoints"
              f"{' (quick set)' if quick else ''}\n")

    results = probe_all(endpoints, quick=quick, include_throughput=True)

    run_id: int | None = None
    if store_results:
        conn = store.connect()
        try:
            run_id = store.start_run(
                conn, dut_backend="macos", dut_identity=f"{network}/{band}",
                notes="kpi measurement run",
            )
            for r in results:
                store.record_kpi(
                    conn,
                    run_id=run_id,
                    network=network,
                    band=band,
                    endpoint_name=r.endpoint,
                    endpoint_host=r.host,
                    probe=r.probe,
                    value=r.value,
                    unit=r.unit,
                    ok=r.ok,
                    error=r.error,
                )
            store.finish_run(conn, run_id, 0)
        finally:
            conn.close()

    if verbose:
        ok = [r for r in results if r.ok]
        failed = [r for r in results if not r.ok]
        for r in results:
            print(" ", r)
        print(f"\n{len(ok)} succeeded, {len(failed)} failed")

        # Per-probe summary across endpoints, so the shape of the connection shows.
        by_probe: dict[str, list[float]] = {}
        for r in ok:
            if r.value is not None and r.unit == "ms":
                by_probe.setdefault(r.probe, []).append(r.value)
        if by_probe:
            print("\nacross endpoints:")
            for probe, values in sorted(by_probe.items()):
                print(f"  {probe:<16} {summarise(values).describe()}")

        # Call-quality estimate from the best available path.
        rtts = [r.value for r in ok if r.probe == "icmp_rtt" and r.value]
        jitters = [r.value for r in ok if r.probe == "jitter" and r.value]
        losses = [r.value for r in ok if r.probe == "loss" and r.value is not None]
        if rtts:
            mos = mos_estimate(min(rtts), min(jitters) if jitters else 0.0,
                               min(losses) if losses else 0.0)
            print(f"\nestimated call quality: MOS {mos:.2f} ({classify_mos(mos)})")

        if run_id:
            print(f"\nstored as run_id={run_id}")
    return run_id, results


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="measure network KPIs")
    ap.add_argument("--quick", action="store_true", help="fast subset of endpoints")
    ap.add_argument("--baseline", action="store_true",
                    help="rebuild baselines from stored history, then exit")
    ap.add_argument("--check", action="store_true",
                    help="after measuring, compare against baselines")
    ap.add_argument("--no-store", action="store_true")
    args = ap.parse_args(argv)

    if args.baseline:
        conn = store.connect()
        try:
            built = rebuild_baselines(conn)
            print(f"rebuilt {len(built)} baselines")
            for b in sorted(built, key=lambda x: x.scope_key):
                print(f"  {b.scope_key:<52} n={b.n:<4} median={b.median:8.2f}{b.unit} "
                      f"mad={b.mad:6.2f}")
        finally:
            conn.close()
        return 0

    run_id, _results = run_measurements(quick=args.quick, store_results=not args.no_store)

    if args.check and run_id:
        conn = store.connect()
        try:
            findings = detect_regressions(conn, run_id)
            regressions = [f for f in findings if f.is_regression]
            print(f"\n=== regression check ({len(findings)} scopes) ===")
            for f in sorted(findings, key=lambda x: x.scope_key):
                if f.verdict is not Verdict.OK or f.is_regression:
                    print(" ", f)
            print(f"\n{len(regressions)} regression(s) detected")
            return 1 if regressions else 0
        finally:
            conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
