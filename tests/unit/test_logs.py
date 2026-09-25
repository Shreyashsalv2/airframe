"""Tests for the log-analysis layer: parsing, template mining, timeline correlation.

These three modules are the input to everything downstream — the ML features, the
triage bundle and the dashboard all consume their output. A silent bug here does not
announce itself; it degrades the quality of every layer above and looks like a problem
somewhere else entirely.
"""

from __future__ import annotations

import pytest

from airframe.logs.drain import PARAM, DrainMiner, mask, similarity, tokenise
from airframe.logs.parse import (
    LogLine,
    extract_fields,
    parse_lines,
    parse_macos_line,
    parse_sim_line,
    summarise,
)
from airframe.logs.timeline import Source, build

# A real line from the simulator, copied verbatim so the test fails if the format drifts.
SIM_LINE = (
    "2025-01-01T00:00:01.240Z [   1240ms] <NOTICE> wifid     : "
    "assoc resp status=0 aid=19 bssid=be:14:66:79:d2:d6 elapsed_ms=16"
)
MACOS_LINE = (
    "2026-09-25 14:32:01.123 Df wifid[123:456] [com.apple.wifi:Client] "
    "scan complete networks=2"
)


# ---------------------------------------------------------------- parsing


class TestSimLineParsing:
    def test_parses_all_columns(self) -> None:
        line = parse_sim_line(SIM_LINE)
        assert line is not None
        assert line.monotonic_ms == 1240
        assert line.level == "NOTICE"
        assert line.component == "wifid"
        assert line.timestamp == "2025-01-01T00:00:01.240Z"
        assert line.message.startswith("assoc resp")

    def test_extracts_key_value_fields(self) -> None:
        line = parse_sim_line(SIM_LINE)
        assert line is not None
        assert line.fields["status"] == "0"
        assert line.fields["aid"] == "19"
        assert line.fields["bssid"] == "be:14:66:79:d2:d6"

    def test_get_int_coerces_and_defaults(self) -> None:
        line = parse_sim_line(SIM_LINE)
        assert line is not None
        assert line.get_int("status") == 0
        assert line.get_int("bssid") is None, "a MAC is not an int"
        assert line.get_int("absent", 42) == 42

    def test_returns_none_for_a_non_sim_line(self) -> None:
        assert parse_sim_line("this is not a log line") is None

    @pytest.mark.parametrize("level,is_error",
                             [("ERROR", True), ("WARN", True), ("INFO", False),
                              ("DEBUG", False), ("NOTICE", False)])
    def test_error_classification(self, level: str, is_error: bool) -> None:
        assert LogLine(raw="", message="x", level=level).is_error is is_error


class TestMacosLineParsing:
    def test_parses_unified_log_format(self) -> None:
        line = parse_macos_line(MACOS_LINE)
        assert line is not None
        assert line.component == "wifid"
        assert line.level == "DEBUG", "Df maps to DEBUG"
        assert "scan complete" in line.message
        assert line.source == "macos"

    def test_unknown_level_flag_falls_back_to_info(self) -> None:
        line = parse_macos_line("2026-09-25 14:32:01.123 Zz proc[1:2] something")
        assert line is not None
        assert line.level == "INFO"


class TestFieldExtraction:
    def test_handles_quoted_values(self) -> None:
        fields = extract_fields('ssid="my network" channel=36')
        assert fields["ssid"] == "my network"
        assert fields["channel"] == "36"

    def test_returns_empty_for_prose(self) -> None:
        assert extract_fields("open network, skipping 4-way handshake") == {}


class TestMixedStreamParsing:
    def test_autodetects_both_formats_in_one_stream(self) -> None:
        lines = parse_lines([SIM_LINE, MACOS_LINE])
        assert len(lines) == 2
        assert {line.source for line in lines} == {"sim", "macos"}

    def test_unparseable_lines_are_kept_not_dropped(self) -> None:
        """A traceback or stack dump never matches a line regex, and is exactly the
        content you most want during triage. Dropping it would be convenient and wrong.
        """
        lines = parse_lines([SIM_LINE, "  File \"x.py\", line 3, in foo", "    raise"])
        assert len(lines) == 3
        assert lines[1].component == "unparsed"
        assert "x.py" in lines[1].message

    def test_unparsed_lines_inherit_the_previous_timestamp(self) -> None:
        """So a traceback lands at the right place on the timeline rather than at 0ms."""
        lines = parse_lines([SIM_LINE, "continuation of the above"])
        assert lines[1].monotonic_ms == lines[0].monotonic_ms == 1240

    def test_blank_lines_are_skipped(self) -> None:
        assert len(parse_lines([SIM_LINE, "", "   ", SIM_LINE])) == 2


class TestSummarise:
    def _transition_log(self) -> list[str]:
        return [
            "2025-01-01T00:00:00.000Z [      0ms] <DEBUG > wifid     : "
            "state transition from=IDLE event=SCAN_START to=SCANNING",
            "2025-01-01T00:00:01.000Z [   1000ms] <DEBUG > wifid     : "
            "state transition from=SCANNING event=AUTH_START to=AUTHENTICATING",
            "2025-01-01T00:00:02.000Z [   2000ms] <ERROR > wifid     : "
            "deauth received reason=15 reason_name=FOURWAY_HANDSHAKE_TIMEOUT",
        ]

    def test_reconstructs_the_state_path(self) -> None:
        summary = summarise(parse_lines(self._transition_log()))
        assert summary.state_transitions[0][1:] == ("IDLE", "SCANNING")
        assert summary.final_state == "AUTHENTICATING"

    def test_collects_reason_codes_and_errors(self) -> None:
        summary = summarise(parse_lines(self._transition_log()))
        assert summary.reason_codes == [15]
        assert len(summary.errors) == 1
        assert summary.by_level["ERROR"] == 1

    def test_duration_spans_the_log(self) -> None:
        assert summarise(parse_lines(self._transition_log())).duration_ms == 2000

    def test_empty_input_does_not_crash(self) -> None:
        summary = summarise([])
        assert summary.total == 0
        assert summary.final_state is None
        assert summary.describe()


# ---------------------------------------------------------------- drain


class TestMasking:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("bssid=be:14:66:79:d2:d6", "bssid=<MAC>"),
            ("server=192.168.1.1", "server=<IP>"),
            ("flags=0xC007", "flags=<HEX>"),
            ("elapsed_ms=1640", "elapsed_ms=<NUM>"),
            ("rate=54.5", "rate=<FLOAT>"),
        ],
    )
    def test_volatile_values_are_masked(self, text: str, expected: str) -> None:
        assert mask(text) == expected

    def test_masking_prevents_per_bssid_template_explosion(self) -> None:
        """The single most important reason masking exists.

        Without it, every distinct BSSID produces its own "template" and the miner
        returns thousands of one-hit entries — technically correct, completely useless.
        """
        miner = DrainMiner()
        for i in range(50):
            miner.add(f"assoc resp status=0 aid={i} bssid=02:aa:bb:cc:dd:{i:02x}")
        assert len(miner.templates) == 1, (
            f"50 BSSIDs produced {len(miner.templates)} templates; masking is not working"
        )
        assert miner.templates[0].hits == 50


class TestSimilarity:
    def test_identical_token_lists_score_one(self) -> None:
        assert similarity(["a", "b", "c"], ["a", "b", "c"]) == 1.0

    def test_wildcards_count_as_matching(self) -> None:
        """This is what lets a template keep generalising as it absorbs more lines."""
        assert similarity(["a", PARAM, "c"], ["a", "zzz", "c"]) == 1.0

    def test_different_lengths_score_zero(self) -> None:
        assert similarity(["a", "b"], ["a", "b", "c"]) == 0.0

    def test_empty_scores_zero(self) -> None:
        assert similarity([], []) == 0.0


class TestDrainMiner:
    def test_merges_variants_of_one_statement(self) -> None:
        miner = DrainMiner()
        miner.add("assoc resp status=0 aid=19 elapsed_ms=16")
        miner.add("assoc resp status=0 aid=7 elapsed_ms=22")
        assert len(miner.templates) == 1
        assert miner.templates[0].hits == 2

    def test_keeps_genuinely_different_statements_apart(self) -> None:
        miner = DrainMiner()
        miner.add("assoc resp status=0 aid=19")
        miner.add("DHCPDISCOVER iface=en0")
        miner.add("scan complete networks=2")
        assert len(miner.templates) == 3

    def test_differing_positions_become_wildcards(self) -> None:
        miner = DrainMiner()
        miner.add("auth request algo=OPEN seq=1")
        miner.add("auth request algo=SAE seq=1")
        template = miner.templates[0]
        assert PARAM in template.tokens
        assert template.param_count >= 1

    def test_match_finds_a_template_without_adding(self) -> None:
        miner = DrainMiner()
        miner.add("scan complete networks=2")
        before = len(miner.templates)
        found = miner.match("scan complete networks=9")
        assert found is not None
        assert len(miner.templates) == before, "match() must not mutate the miner"

    def test_match_returns_none_for_an_unseen_statement(self) -> None:
        miner = DrainMiner()
        miner.add("scan complete networks=2")
        assert miner.match("something entirely unrelated happened here now") is None

    def test_histogram_counts_by_template(self) -> None:
        miner = DrainMiner()
        for _ in range(3):
            miner.add("scan complete networks=2")
        miner.add("DHCPACK ip=192.168.1.5")
        histogram = miner.histogram(
            ["scan complete networks=4", "scan complete networks=1", "DHCPACK ip=10.0.0.1"]
        )
        assert sum(histogram.values()) == 3
        assert len(histogram) == 2

    def test_compression_on_a_realistic_log(self) -> None:
        """The headline claim, asserted rather than quoted."""
        miner = DrainMiner()
        for run in range(40):
            miner.add(f"sim start seed={run} channel=36")
            miner.add(f"scan complete networks={run % 3}")
            miner.add(f"auth response bssid=02:aa:bb:cc:dd:{run:02x} status=0")
            miner.add(f"assoc resp status=0 aid={run} elapsed_ms={run * 3}")
            miner.add(f"DHCPACK ip=192.168.1.{run} lease_s=86400")
        total = 200
        assert miner.compression_ratio(total) > 0.95, (
            f"{len(miner.templates)} templates from {total} lines is not enough compression"
        )

    def test_tree_bounded_by_max_children(self) -> None:
        """A pathological log must not grow the tree without limit."""
        miner = DrainMiner(max_children=4)
        for i in range(200):
            miner.add(f"unique{i} token here")
        assert len(miner.templates) < 200, "the catch-all branch is not collapsing"

    def test_tokenise_masks_before_splitting(self) -> None:
        assert tokenise("ip=192.168.1.1 n=5") == ["ip=<IP>", "n=<NUM>"]


# ---------------------------------------------------------------- timeline


class TestTimeline:
    def _lines(self) -> list[LogLine]:
        return parse_lines([
            "2025-01-01T00:00:00.000Z [      0ms] <INFO  > wifid     : scan request",
            "2025-01-01T00:00:01.000Z [   1000ms] <WARN  > supplicant: retransmitting M2",
            "2025-01-01T00:00:02.000Z [   2000ms] <ERROR > wifid     : deauth reason=15",
            "2025-01-01T00:00:09.000Z [   9000ms] <INFO  > wifid     : idle",
        ])

    def test_orders_events_by_monotonic_time(self) -> None:
        timeline = build(log_lines=self._lines())
        times = [e.monotonic_ms for e in timeline.events]
        assert times == sorted(times)

    def test_severity_is_carried_through(self) -> None:
        timeline = build(log_lines=self._lines())
        assert len(timeline.errors()) == 1
        assert timeline.errors()[0].monotonic_ms == 2000

    def test_around_windows_on_a_timestamp(self) -> None:
        timeline = build(log_lines=self._lines())
        near = timeline.around(1000, window_ms=1100)
        assert {e.monotonic_ms for e in near} == {0, 1000, 2000}

    def test_first_error_context_finds_the_causal_window(self) -> None:
        """The primary triage query: what was happening around the first error."""
        timeline = build(log_lines=self._lines())
        context = timeline.first_error_context(window_ms=1500)
        assert any("retransmitting M2" in e.detail for e in context)
        assert not any(e.monotonic_ms == 9000 for e in context), "9s away is not context"

    def test_no_errors_gives_empty_context(self) -> None:
        clean = parse_lines([
            "2025-01-01T00:00:00.000Z [      0ms] <INFO  > wifid     : all good"
        ])
        assert build(log_lines=clean).first_error_context() == []

    def test_render_produces_readable_output(self) -> None:
        text = build(log_lines=self._lines()).render()
        assert "timeline:" in text
        assert "2000ms" in text
        assert "X" in text, "errors should be marked"

    def test_empty_timeline_renders_a_message_not_a_crash(self) -> None:
        assert "empty" in build().render().lower()

    def test_counts_are_tracked_per_source(self) -> None:
        timeline = build(log_lines=self._lines())
        assert timeline.log_count == 4
        assert timeline.frame_count == 0
        assert all(e.source is Source.LOG for e in timeline.events)

    def test_kpi_samples_merge_onto_the_same_clock(self) -> None:
        timeline = build(log_lines=self._lines(),
                         kpi_samples=[(1500, "icmp_rtt", 23.4, "ms")])
        kpi_events = [e for e in timeline.events if e.source is Source.KPI]
        assert len(kpi_events) == 1
        assert kpi_events[0].monotonic_ms == 1500
        # It must land between the 1000ms and 2000ms log lines.
        positions = [e.monotonic_ms for e in timeline.events]
        assert positions.index(1500) == positions.index(2000) - 1
