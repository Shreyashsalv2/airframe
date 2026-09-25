#!/usr/bin/env python3
"""Generate the capture + log corpus the analysis layers are developed against.

Runs the C++ simulator across a spread of scenarios and faults, with traffic, so
that every artifact in `data/` is reproducible from a single command. The ML and
triage layers train and are evaluated on this corpus, so regenerating it must be
deterministic — every run is seeded, and re-running produces byte-identical files.

Usage:
    python scripts/build_corpus.py [--out data] [--runs-per-fault 3]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SIM = REPO / "sim" / "build" / "airframe-sim"

# (scenario, fault, probability) — the spread the analysis layers must handle.
SCENARIOS = ["wpa2", "wpa3", "open", "enterprise", "wifi6e", "legacy"]
FAULTS = [
    "NONE",
    "AUTH_TIMEOUT",
    "ASSOC_REJECT",
    "FOURWAY_M3_TIMEOUT",
    "PMK_MISMATCH",
    "DHCP_NAK",
    "SCAN_EMPTY",
    "LOW_RSSI",
    "CHANNEL_BUSY",
    "BEACON_LOSS",
    "DEAUTH",
]


#: Faults that cannot fire in a given scenario, because the stage they target does
#: not exist there. An open network has no 4-way handshake, so injecting a handshake
#: fault produces a perfectly successful run -- which, labelled as a fault, poisons
#: every evaluation downstream. See BUILD_JOURNAL.md #15.
INAPPLICABLE: dict[str, set[str]] = {
    "open": {"FOURWAY_M3_TIMEOUT", "PMK_MISMATCH"},
}


def is_applicable(scenario: str, fault: str) -> bool:
    return fault not in INAPPLICABLE.get(scenario, set())


def run_one(
    out_dir: Path, scenario: str, fault: str, seed: int, *, run_ms: int = 3000
) -> dict | None:
    """One simulator session -> one pcap, one log, one summary."""
    tag = f"{scenario}_{fault}_{seed}"
    pcap = out_dir / "pcaps" / f"{tag}.pcap"
    log = out_dir / "logs" / f"{tag}.log"
    summary = out_dir / "logs" / f"{tag}.json"
    for p in (pcap.parent, log.parent):
        p.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(SIM),
        "--scenario", scenario,
        "--fault", fault,
        "--seed", str(seed),
        "--pcap", str(pcap),
        "--log", str(log),
        "--summary", str(summary),
        "--run-ms", str(run_ms),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    # Exit 1 means the connection failed, which for most of these is the intended
    # outcome -- so a non-zero status is expected, not an error.
    if proc.returncode not in (0, 1):
        print(f"  !! {tag}: simulator exited {proc.returncode}: {proc.stderr[:200]}",
              file=sys.stderr)
        return None
    try:
        return {"tag": tag, "scenario": scenario, "fault": fault, "seed": seed,
                "pcap": str(pcap), "log": str(log),
                "summary": json.loads(summary.read_text())}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  !! {tag}: could not read summary: {exc}", file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(REPO / "data"))
    ap.add_argument("--runs-per-fault", type=int, default=3,
                    help="distinct seeds per (scenario, fault) pair")
    ap.add_argument("--flake-runs", type=int, default=30,
                    help="probabilistic runs, used as flake-detector ground truth")
    args = ap.parse_args()

    if not SIM.exists():
        print(f"simulator not built at {SIM}\n"
              "run: cmake -S sim -B sim/build && cmake --build sim/build -j8",
              file=sys.stderr)
        return 1

    out = Path(args.out)
    manifest: list[dict] = []

    print("=== deterministic corpus ===")
    seed = 1000
    for scenario in SCENARIOS:
        for fault in FAULTS:
            # 6GHz forbids open/WPA2, so skip pairings the DUT would refuse for an
            # unrelated reason -- they would pollute the corpus with a failure mode
            # that has nothing to do with the fault under test.
            if not is_applicable(scenario, fault):
                continue
            for _ in range(args.runs_per_fault):
                seed += 1
                entry = run_one(out, scenario, fault, seed)
                if entry:
                    manifest.append(entry)
        print(f"  {scenario:<12} done ({len([m for m in manifest if m['scenario'] == scenario])} runs)")

    print("\n=== flake corpus (probabilistic faults, ground truth known) ===")
    flake_manifest: list[dict] = []
    for fault in ("FOURWAY_M3_TIMEOUT", "DHCP_NAK", "ASSOC_REJECT"):
        for i in range(args.flake_runs):
            seed += 1
            tag = f"flake_{fault}_{seed}"
            pcap = out / "pcaps" / f"{tag}.pcap"
            log = out / "logs" / f"{tag}.log"
            summary = out / "logs" / f"{tag}.json"
            proc = subprocess.run(
                [str(SIM), "--scenario", "wpa2", "--fault", fault,
                 "--probability", "0.5", "--seed", str(seed),
                 "--pcap", str(pcap), "--log", str(log), "--summary", str(summary),
                 "--run-ms", "1000"],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode in (0, 1):
                flake_manifest.append({
                    "tag": tag, "fault": fault, "seed": seed,
                    "injected": True, "fired": proc.returncode == 1,
                    "pcap": str(pcap), "log": str(log),
                })
            del i
        fired = sum(1 for m in flake_manifest if m["fault"] == fault and m["fired"])
        total = sum(1 for m in flake_manifest if m["fault"] == fault)
        print(f"  {fault:<20} fired {fired}/{total} ({fired / total:.0%})")

    manifest_path = out / "corpus_manifest.json"
    manifest_path.write_text(json.dumps(
        {"deterministic": manifest, "flake": flake_manifest}, indent=2, default=str))

    print(f"\n{len(manifest)} deterministic + {len(flake_manifest)} flake runs")
    print(f"manifest: {manifest_path}")
    print(f"pcaps   : {len(list((out / 'pcaps').glob('*.pcap')))}")
    print(f"logs    : {len(list((out / 'logs').glob('*.log')))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
