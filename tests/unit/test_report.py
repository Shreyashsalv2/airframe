"""Tests for the HTML dashboard generator.

A report generator is easy to leave untested because "it looks fine". The failure modes
that matter are not visual:

* it crashes on an empty or partial database (the state every new clone is in),
* it interpolates untrusted strings — test names and failure messages — straight into
  HTML, which is an injection hole and also just breaks the page,
* it silently loses a panel when a query returns nothing.

None of those are visible by looking at a screenshot of a populated dashboard.
"""

from __future__ import annotations

import re

from airframe.report.html import (
    build_html,
    data_table,
    gather,
    hbar_chart,
    stacked_outcome_chart,
    stat_tile,
    write_report,
)
from airframe.store import db as store

# ---------------------------------------------------------------- components


class TestComponents:
    def test_stat_tile_renders_all_parts(self) -> None:
        html = stat_tile("pass rate", "98.6%", "1,461 of 1,482", "good")
        assert "pass rate" in html and "98.6%" in html
        assert 'data-status="good"' in html

    def test_status_uses_an_icon_not_colour_alone(self) -> None:
        """Colour alone fails for colourblind readers and in forced-colours mode."""
        assert "ico" in stat_tile("x", "1", "note", "critical")

    def test_hbar_chart_includes_direct_labels(self) -> None:
        """Three light-mode series colours are below 3:1 contrast, so the palette's
        relief rule requires visible labels. This asserts they are present."""
        html = hbar_chart([("endpoint", 23.4, "1")], unit="ms")
        assert "23.4" in html

    def test_hbar_chart_always_ships_a_table_view(self) -> None:
        html = hbar_chart([("a", 1.0, "1")])
        assert "<table" in html and "table view" in html

    def test_hbar_chart_respects_decimal_places(self) -> None:
        assert "18</div>" in hbar_chart([("f", 18.0, "1")], decimals=0)
        assert "18.0" in hbar_chart([("f", 18.0, "1")], decimals=1)

    def test_zero_values_still_render_a_visible_sliver(self) -> None:
        """A bar of width 0 is indistinguishable from a missing row."""
        html = hbar_chart([("zero", 0.0, "1"), ("big", 100.0, "1")])
        widths = [float(m) for m in re.findall(r"width:([\d.]+)%", html)]
        assert min(widths) > 0

    def test_empty_chart_says_so(self) -> None:
        assert "no data" in hbar_chart([])
        assert "no results" in stacked_outcome_chart([])

    def test_stacked_chart_has_a_legend(self) -> None:
        """Identity must never be carried by colour alone for two or more series."""
        html = stacked_outcome_chart(
            [{"suite": "unit", "total": 10, "passed": 8, "failed": 1, "skipped": 1}]
        )
        assert "legend" in html
        assert "passed" in html and "failed" in html and "skipped" in html

    def test_data_table_empty_message_is_customisable(self) -> None:
        assert "nothing here" in data_table(["a"], [], empty="nothing here")


# ---------------------------------------------------------------- escaping


class TestEscaping:
    def test_hostile_strings_are_escaped_in_tiles(self) -> None:
        html = stat_tile("<script>alert(1)</script>", "v", "n")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_hostile_strings_are_escaped_in_tables(self) -> None:
        html = data_table(["col"], [['<img src=x onerror="alert(1)">']])
        assert "<img" not in html
        assert "&lt;img" in html

    def test_test_names_with_brackets_survive(self) -> None:
        """Parametrized node IDs are full of brackets and quotes."""
        nodeid = 'tests/x.py::test_y[5GHz-80-wpa3_sae-11ax]'
        assert "5GHz-80-wpa3_sae-11ax" in data_table(["t"], [[nodeid]])


# ---------------------------------------------------------------- full page


class TestFullPage:
    def test_renders_against_an_empty_database(self, tmp_path) -> None:
        """The state every fresh clone is in. Must not crash."""
        conn = store.connect(tmp_path / "empty.db")
        try:
            html = build_html(gather(conn))
        finally:
            conn.close()
        assert "<!DOCTYPE html>" in html
        assert "airframe" in html

    def test_renders_with_partial_data(self, tmp_path) -> None:
        """Results but no KPIs, no baselines, no triage — a very common state."""
        conn = store.connect(tmp_path / "partial.db")
        try:
            rid = store.start_run(conn, dut_backend="sim", seed=1)
            store.record_result(conn, run_id=rid, nodeid="t::a", outcome="passed",
                                suite="unit")
            store.record_result(conn, run_id=rid, nodeid="t::b", outcome="failed",
                                suite="unit", failure_message="assert 1 == 2")
            html = build_html(gather(conn))
        finally:
            conn.close()
        assert "assert 1 == 2" in html
        assert "no baselines yet" in html, "empty panels must explain themselves"

    def test_both_theme_blocks_are_present(self) -> None:
        """Dark mode is selected, not an automatic flip — and it must cover both the
        OS setting and an explicit theme toggle."""
        conn = store.connect(":memory:")
        store.init_schema(conn)
        try:
            html = build_html(gather(conn))
        finally:
            conn.close()
        assert "prefers-color-scheme: dark" in html
        assert '[data-theme="dark"]' in html

    def test_page_is_self_contained(self, tmp_path) -> None:
        """No external CSS or JS: the dashboard has to work from a file:// URL and as
        a CI artifact with no network."""
        conn = store.connect(tmp_path / "t.db")
        try:
            html = build_html(gather(conn))
        finally:
            conn.close()
        assert "<link" not in html
        assert "<script" not in html

    def test_write_report_creates_the_file(self, tmp_path) -> None:
        out = tmp_path / "nested" / "index.html"
        path = write_report(out, db_path=str(tmp_path / "t.db"))
        assert path.exists()
        assert path.stat().st_size > 1000
