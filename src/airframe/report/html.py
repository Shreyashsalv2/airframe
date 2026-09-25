"""HTML dashboard — the shareable view of everything the rig knows.

Design notes (this follows a validated visualisation method, not taste):

* **KPI row of stat tiles** for the headline numbers. A handful of scalars is not a
  chart; making it one adds ink without adding information.
* **Horizontal bars** for magnitude-by-category (results per suite, cluster sizes,
  latency per endpoint) — horizontal because the category labels are long words, and
  rotated axis labels are a readability tax.
* **No dual-axis charts anywhere.** Latency and throughput have different scales, so
  they get separate panels rather than two y-axes on one plot.
* **Every chart has a table view.** Three of the light-mode series colours sit below
  3:1 contrast on the light surface, so the validated palette's relief rule requires
  visible labels or a table — both are provided.
* **Dark mode is selected, not flipped.** The dark values are the same hues re-stepped
  for the dark surface, and were validated against it independently.

The palette is the reference categorical set, validated in both modes:
worst adjacent CVD ΔE 9.1 light / 8.4 dark, normal-vision ΔE 22.9 / 19.8.
"""

from __future__ import annotations

import html
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = REPO_ROOT / "data" / "report" / "index.html"


def _esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


@dataclass
class Panel:
    title: str
    subtitle: str
    body: str


# ---------------------------------------------------------------- data gathering


def gather(conn: sqlite3.Connection) -> dict[str, Any]:
    """Pull everything the dashboard needs in one pass."""
    out: dict[str, Any] = {}

    out["runs"] = [
        dict(r)
        for r in conn.execute(
            """SELECT r.id, r.started_at, r.dut_backend, r.dut_identity,
                      COUNT(res.id) n_tests,
                      SUM(CASE WHEN res.outcome='passed' THEN 1 ELSE 0 END) n_passed,
                      SUM(CASE WHEN res.outcome IN ('failed','error') THEN 1 ELSE 0 END)
                        n_failed,
                      SUM(CASE WHEN res.outcome='skipped' THEN 1 ELSE 0 END) n_skipped,
                      SUM(res.is_flake) n_flaky
               FROM runs r LEFT JOIN results res ON res.run_id = r.id
               GROUP BY r.id HAVING n_tests > 0 ORDER BY r.id DESC LIMIT 25"""
        )
    ]

    out["by_suite"] = [
        dict(r)
        for r in conn.execute(
            """SELECT suite,
                      COUNT(*) total,
                      SUM(CASE WHEN outcome='passed' THEN 1 ELSE 0 END) passed,
                      SUM(CASE WHEN outcome IN ('failed','error') THEN 1 ELSE 0 END) failed,
                      SUM(CASE WHEN outcome='skipped' THEN 1 ELSE 0 END) skipped
               FROM v_final_results WHERE suite IS NOT NULL
               GROUP BY suite ORDER BY total DESC"""
        )
    ]

    out["flakes"] = [
        dict(r) for r in conn.execute("SELECT * FROM v_flake_rate LIMIT 15")
    ]

    out["kpi"] = [
        dict(r)
        for r in conn.execute(
            """SELECT endpoint_name, probe, unit, COUNT(*) n,
                      ROUND(AVG(value),2) avg_value,
                      ROUND(MIN(value),2) min_value,
                      ROUND(MAX(value),2) max_value
               FROM kpi_samples WHERE ok=1 AND value IS NOT NULL
               GROUP BY endpoint_name, probe ORDER BY probe, endpoint_name"""
        )
    ]

    out["baselines"] = [
        dict(r)
        for r in conn.execute(
            "SELECT scope_key, n, median, mad, p95, unit FROM baselines ORDER BY scope_key"
        )
    ]

    out["triage"] = [
        dict(r)
        for r in conn.execute(
            """SELECT t.root_cause, t.confidence, t.suggested_owner, t.provider,
                      t.model, t.tool_calls, res.nodeid
               FROM triage_reports t LEFT JOIN results res ON res.id = t.result_id
               ORDER BY t.id DESC LIMIT 15"""
        )
    ]

    out["latest_failures"] = [
        dict(r)
        for r in conn.execute(
            """SELECT nodeid, failure_message, suite FROM v_final_results
               WHERE outcome IN ('failed','error')
               ORDER BY run_id DESC, id DESC LIMIT 20"""
        )
    ]

    # Corpus / clustering, read from disk rather than recomputed: the dashboard must
    # render fast and must not depend on a 30-second ML run completing.
    manifest = REPO_ROOT / "data" / "corpus_manifest.json"
    out["corpus"] = {}
    if manifest.exists():
        data = json.loads(manifest.read_text())
        faults: dict[str, int] = {}
        for entry in data.get("deterministic", []):
            faults[entry["fault"]] = faults.get(entry["fault"], 0) + 1
        out["corpus"] = {
            "n_runs": len(data.get("deterministic", [])),
            "n_flake_runs": len(data.get("flake", [])),
            "faults": dict(sorted(faults.items(), key=lambda kv: -kv[1])),
        }

    out["counts"] = {
        table: conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
        for table in ("runs", "results", "kpi_samples", "baselines", "triage_reports")
    }
    out["pcaps"] = len(list((REPO_ROOT / "data" / "pcaps").glob("*.pcap")))
    return out


# ---------------------------------------------------------------- components


def stat_tile(label: str, value: str, note: str = "", status: str = "") -> str:
    """A single headline number. Status is carried by an icon + label, never colour alone."""
    icon = {"good": "●", "warning": "▲", "critical": "■"}.get(status, "")
    status_attr = f' data-status="{status}"' if status else ""
    return f"""<div class="tile"{status_attr}>
      <div class="tile-label">{_esc(label)}</div>
      <div class="tile-value">{_esc(value)}</div>
      <div class="tile-note">{f'<span class="ico">{icon}</span> ' if icon else ''}{_esc(note)}</div>
    </div>"""


def hbar_chart(
    rows: list[tuple[str, float, str]],
    *,
    unit: str = "",
    table_headers: tuple[str, ...] = (),
    decimals: int = 2,
) -> str:
    """Horizontal bars with direct value labels, plus a collapsible table view.

    `rows` is (label, value, series-slot). Direct labels are always present, which
    satisfies the palette's relief rule for the lower-contrast slots and removes the
    need for the reader to consult a legend for magnitude.
    """
    if not rows:
        return '<p class="empty">no data yet</p>'
    peak = max(v for _, v, _ in rows) or 1.0
    fmt = f",.{decimals}f"

    bars: list[str] = []
    for label, value, slot in rows:
        pct = max((value / peak) * 100.0, 0.6)     # keep a sliver visible at zero
        bars.append(
            f"""<div class="bar-row">
          <div class="bar-label" title="{_esc(label)}">{_esc(label)}</div>
          <div class="bar-track"><div class="bar-fill" data-series="{slot}"
               style="width:{pct:.2f}%"></div></div>
          <div class="bar-value">{value:{fmt}}{_esc(unit)}</div>
        </div>"""
        )

    headers = table_headers or ("item", "value")
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        f"<tr><td>{_esc(label)}</td><td class='num'>{value:{fmt}}{_esc(unit)}</td></tr>"
        for label, value, _ in rows
    )
    return f"""<div class="chart">{''.join(bars)}</div>
    <details class="table-view"><summary>table view</summary>
      <table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>
    </details>"""


def stacked_outcome_chart(rows: list[dict[str, Any]]) -> str:
    """Stacked bars per suite. A 2px surface gap separates segments, per the mark spec."""
    if not rows:
        return '<p class="empty">no results yet</p>'
    peak = max(r["total"] for r in rows) or 1

    bars: list[str] = []
    for row in rows:
        total = row["total"] or 1
        segments = [
            ("passed", row["passed"] or 0, "3"),
            ("failed", row["failed"] or 0, "8"),
            ("skipped", row["skipped"] or 0, "muted"),
        ]
        inner = "".join(
            f'<span class="seg" data-series="{slot}" style="flex:{count}"'
            f' title="{name}: {count}"></span>'
            for name, count, slot in segments
            if count
        )
        bars.append(
            f"""<div class="bar-row">
          <div class="bar-label">{_esc(row['suite'])}</div>
          <div class="bar-track" style="width:{(total / peak) * 100:.1f}%">
            <div class="stack">{inner}</div>
          </div>
          <div class="bar-value">{total:,}</div>
        </div>"""
        )

    body = "".join(
        f"<tr><td>{_esc(r['suite'])}</td><td class='num'>{r['passed'] or 0}</td>"
        f"<td class='num'>{r['failed'] or 0}</td><td class='num'>{r['skipped'] or 0}</td>"
        f"<td class='num'>{r['total']}</td></tr>"
        for r in rows
    )
    legend = """<div class="legend">
      <span><i data-series="3"></i>passed</span>
      <span><i data-series="8"></i>failed</span>
      <span><i data-series="muted"></i>skipped</span>
    </div>"""
    return f"""{legend}<div class="chart">{''.join(bars)}</div>
    <details class="table-view"><summary>table view</summary>
      <table><thead><tr><th>suite</th><th>passed</th><th>failed</th><th>skipped</th>
      <th>total</th></tr></thead><tbody>{body}</tbody></table>
    </details>"""


def data_table(headers: list[str], rows: list[list[str]], *, empty: str = "no data") -> str:
    if not rows:
        return f'<p class="empty">{_esc(empty)}</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


# ---------------------------------------------------------------- assembly


def build_html(data: dict[str, Any]) -> str:
    counts = data["counts"]
    runs = data["runs"]
    latest = runs[0] if runs else {}

    total_tests = sum(r["n_tests"] or 0 for r in runs)
    total_failed = sum(r["n_failed"] or 0 for r in runs)
    total_flaky = sum(r["n_flaky"] or 0 for r in runs)
    pass_rate = (
        100.0 * (total_tests - total_failed) / total_tests if total_tests else 0.0
    )

    tiles = "".join([
        stat_tile("pass rate", f"{pass_rate:.1f}%",
                  f"{total_tests - total_failed:,} of {total_tests:,} attempts",
                  "good" if pass_rate >= 99 else ("warning" if pass_rate >= 90 else "critical")),
        stat_tile("test runs", f"{counts['runs']:,}",
                  f"latest: {latest.get('dut_backend', 'n/a')}"),
        stat_tile("flaky attempts", f"{total_flaky:,}",
                  "recorded, not hidden",
                  "warning" if total_flaky else "good"),
        stat_tile("captures", f"{data['pcaps']:,}", "802.11 pcap files"),
        stat_tile("KPI samples", f"{counts['kpi_samples']:,}",
                  f"{counts['baselines']} baselines learned"),
        stat_tile("triage reports", f"{counts['triage_reports']:,}", "LLM root causes"),
    ])

    panels: list[Panel] = []

    panels.append(Panel(
        "Results by suite",
        "final outcome per test, latest attempt only",
        stacked_outcome_chart(data["by_suite"]),
    ))

    # Latency by endpoint. Separate panel from throughput — never a dual axis.
    latency = [
        (f"{r['endpoint_name']}·{r['probe']}", float(r["avg_value"]), "1")
        for r in data["kpi"]
        if r["unit"] == "ms" and r["avg_value"] is not None
    ][:14]
    panels.append(Panel(
        "Network latency by endpoint",
        "mean of stored samples, milliseconds — Indian ISP resolvers, CDN edges and gateway",
        hbar_chart(latency, unit="ms", decimals=1,
                   table_headers=("endpoint · probe", "mean latency")),
    ))

    throughput = [
        (f"{r['endpoint_name']}·{r['probe']}", float(r["avg_value"]), "3")
        for r in data["kpi"]
        if r["unit"] == "mbps" and r["avg_value"] is not None
    ]
    if throughput:
        panels.append(Panel(
            "Throughput", "mean of stored samples, Mbps",
            hbar_chart(throughput, unit=" Mbps", decimals=1,
                       table_headers=("endpoint · probe", "mean throughput")),
        ))

    faults = data.get("corpus", {}).get("faults", {})
    if faults:
        panels.append(Panel(
            "Corpus composition by injected fault",
            f"{data['corpus']['n_runs']} deterministic runs + "
            f"{data['corpus']['n_flake_runs']} probabilistic runs, each reproducible from its seed",
            hbar_chart([(name, float(n), "2") for name, n in faults.items()],
                       table_headers=("injected fault", "runs"), decimals=0),
        ))

    panels.append(Panel(
        "Flake leaderboard",
        "tests that passed only after failing — recorded as flakes rather than as passes",
        data_table(
            ["test", "attempts", "failures", "flakes", "rate"],
            [[r["nodeid"], r["attempts"], r["failures"], r["flakes"],
              f"{r['flake_rate']:.0%}"] for r in data["flakes"]],
            empty="no flakes recorded (run `make test-flaky` to demonstrate)",
        ),
    ))

    panels.append(Panel(
        "KPI baselines",
        "median + MAD per network·band·endpoint·probe — robust statistics, "
        "because latency is heavy-tailed",
        data_table(
            ["scope", "n", "median", "MAD", "p95"],
            [[b["scope_key"], b["n"], f"{b['median']:.2f}{b['unit']}",
              f"{b['mad']:.2f}", f"{b['p95']:.2f}" if b["p95"] else "—"]
             for b in data["baselines"][:20]],
            empty="no baselines yet (run `make kpi` a few times, then `make baseline`)",
        ),
    ))

    panels.append(Panel(
        "LLM triage verdicts",
        "root cause, confidence and suggested owner — every claim cites evidence",
        data_table(
            ["test", "root cause", "confidence", "owner", "provider"],
            [[t["nodeid"] or "—", (t["root_cause"] or "")[:140],
              f"{(t['confidence'] or 0):.0%}", t["suggested_owner"] or "—",
              f"{t['provider']}/{t['model']}"] for t in data["triage"]],
            empty="no triage reports yet (run `python -m airframe.triage.agent <tag> --store`)",
        ),
    ))

    panels.append(Panel(
        "Recent failures",
        "most recent first",
        data_table(
            ["suite", "test", "message"],
            [[f["suite"] or "—", f["nodeid"], (f["failure_message"] or "")[:150]]
             for f in data["latest_failures"]],
            empty="no failures recorded",
        ),
    ))

    panel_html = "".join(
        f"""<section class="panel">
      <h2>{_esc(p.title)}</h2>
      <p class="sub">{_esc(p.subtitle)}</p>
      {p.body}
    </section>"""
        for p in panels
    )

    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>airframe</title>
<style>
/* Palette: the validated reference categorical set. Both modes were checked with the
   validator, not by eye. Dark is the same hues re-stepped for the dark surface. */
:root {{
  color-scheme: light;
  --page:           #f9f9f7;
  --surface-1:      #fcfcfb;
  --text-primary:   #0b0b0b;
  --text-secondary: #52514e;
  --text-muted:     #898781;
  --grid:           #e1e0d9;
  --axis:           #c3c2b7;
  --series-1:       #2a78d6;
  --series-2:       #eb6834;
  --series-3:       #1baf7a;
  --series-8:       #e34948;
  --series-muted:   #c3c2b7;
  --good:           #0ca30c;
  --warning:        #fab219;
  --critical:       #d03b3b;
}}
@media (prefers-color-scheme: dark) {{
  :root:where(:not([data-theme="light"])) {{
    color-scheme: dark;
    --page:           #0d0d0d;
    --surface-1:      #1a1a19;
    --text-primary:   #ffffff;
    --text-secondary: #c3c2b7;
    --text-muted:     #898781;
    --grid:           #2c2c2a;
    --axis:           #383835;
    --series-1:       #3987e5;
    --series-2:       #d95926;
    --series-3:       #199e70;
    --series-8:       #e66767;
    --series-muted:   #52514e;
  }}
}}
:root[data-theme="dark"] {{
  color-scheme: dark;
  --page: #0d0d0d; --surface-1: #1a1a19;
  --text-primary: #ffffff; --text-secondary: #c3c2b7; --text-muted: #898781;
  --grid: #2c2c2a; --axis: #383835;
  --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70;
  --series-8: #e66767; --series-muted: #52514e;
}}

* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--page); color: var(--text-primary);
  font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", system-ui, sans-serif;
  -webkit-font-smoothing: antialiased;
}}
.wrap {{ max-width: 1120px; margin: 0 auto; padding: 40px 16px 72px; }}
header {{ margin-bottom: 28px; }}
h1 {{ font-size: 26px; margin: 0 0 6px; letter-spacing: -0.01em; }}
.tagline {{ color: var(--text-secondary); margin: 0 0 4px; }}
.meta {{ color: var(--text-muted); font-size: 13px; font-variant-numeric: tabular-nums; }}

.tiles {{
  display: grid; gap: 12px; margin-bottom: 30px;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
}}
.tile {{
  background: var(--surface-1); border: 1px solid var(--grid);
  border-radius: 10px; padding: 14px 16px;
}}
.tile-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase;
  letter-spacing: 0.06em; }}
.tile-value {{ font-size: 27px; font-weight: 600; margin: 4px 0 2px;
  font-variant-numeric: tabular-nums; letter-spacing: -0.02em; }}
.tile-note {{ font-size: 12.5px; color: var(--text-secondary); }}
/* Status is icon + label, never colour alone. */
.tile[data-status="good"] .ico {{ color: var(--good); }}
.tile[data-status="warning"] .ico {{ color: var(--warning); }}
.tile[data-status="critical"] .ico {{ color: var(--critical); }}

.panel {{
  background: var(--surface-1); border: 1px solid var(--grid);
  border-radius: 10px; padding: 18px 20px 20px; margin-bottom: 18px;
}}
.panel h2 {{ font-size: 16px; margin: 0 0 3px; }}
.panel .sub {{ font-size: 13px; color: var(--text-muted); margin: 0 0 16px; }}

.chart {{ display: flex; flex-direction: column; gap: 7px; }}
.bar-row {{ display: grid; grid-template-columns: 190px 1fr 92px; gap: 12px;
  align-items: center; }}
.bar-label {{ font-size: 12.5px; color: var(--text-secondary); overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; }}
.bar-track {{ background: var(--grid); border-radius: 4px; height: 15px;
  overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 0 4px 4px 0; }}
.bar-value {{ font-size: 12.5px; color: var(--text-secondary); text-align: right;
  font-variant-numeric: tabular-nums; }}
.stack {{ display: flex; height: 100%; gap: 2px; }}  /* 2px surface gap between fills */
.seg {{ display: block; height: 100%; }}
.seg:first-child {{ border-radius: 4px 0 0 4px; }}
.seg:last-child {{ border-radius: 0 4px 4px 0; }}

[data-series="1"] {{ background: var(--series-1); }}
[data-series="2"] {{ background: var(--series-2); }}
[data-series="3"] {{ background: var(--series-3); }}
[data-series="8"] {{ background: var(--series-8); }}
[data-series="muted"] {{ background: var(--series-muted); }}

.legend {{ display: flex; gap: 16px; margin-bottom: 14px; font-size: 12.5px;
  color: var(--text-secondary); }}
.legend span {{ display: inline-flex; align-items: center; gap: 6px; }}
.legend i {{ width: 10px; height: 10px; border-radius: 2px; display: inline-block; }}

table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; font-weight: 600; color: var(--text-muted);
  border-bottom: 1px solid var(--axis); padding: 7px 10px 7px 0;
  font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }}
td {{ padding: 7px 10px 7px 0; border-bottom: 1px solid var(--grid);
  color: var(--text-secondary); vertical-align: top; }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
tr:last-child td {{ border-bottom: none; }}

.table-view {{ margin-top: 14px; }}
.table-view summary {{ font-size: 12.5px; color: var(--text-muted); cursor: pointer;
  padding: 5px 0; }}
.empty {{ color: var(--text-muted); font-size: 13.5px; font-style: italic; margin: 6px 0; }}
footer {{ margin-top: 34px; color: var(--text-muted); font-size: 12.5px;
  line-height: 1.7; }}
code {{ background: var(--grid); padding: 1px 5px; border-radius: 3px; font-size: 12px; }}

@media (max-width: 620px) {{
  .bar-row {{ grid-template-columns: 116px 1fr 72px; gap: 8px; }}
  .wrap {{ padding: 24px 16px 48px; }}
}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>airframe</h1>
  <p class="tagline">Wireless connectivity test automation &amp; AI triage</p>
  <p class="meta">generated {generated} · {counts['results']:,} test attempts ·
     {data['pcaps']:,} captures · {counts['kpi_samples']:,} KPI samples</p>
</header>

<div class="tiles">{tiles}</div>

{panel_html}

<footer>
  Every number here is reproducible. <code>make corpus</code> regenerates the captures
  and logs byte-identically from their seeds; <code>make verify</code> re-runs the whole
  pipeline. Robust statistics (median + MAD) are used throughout for network metrics,
  because latency distributions are heavy-tailed and a single stall destroys a mean.
  Flaky tests are recorded as flakes, never silently converted into passes.
</footer>
</div>
</body>
</html>
"""


def write_report(out_path: str | Path = DEFAULT_OUT, *, db_path: str | None = None) -> Path:
    from airframe.store import db as store

    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = store.connect(db_path)
    try:
        html_text = build_html(gather(conn))
    finally:
        conn.close()
    path.write_text(html_text)
    return path


def _main() -> int:
    import argparse
    import subprocess

    ap = argparse.ArgumentParser(description="build the airframe HTML dashboard")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--open", action="store_true", help="open it in the browser")
    args = ap.parse_args()

    path = write_report(args.out)
    print(f"wrote {path} ({path.stat().st_size:,} bytes)")
    if args.open:
        subprocess.run(["open", str(path)], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
