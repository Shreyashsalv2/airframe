"""Tests for the packet-analysis layer.

Two categories, and the split is deliberate:

* **Corpus tests** run against captures the C++ simulator produced with a *known*
  injected fault. Because the ground truth is known, the assertion can be exact:
  "given a capture of an M3 timeout, the forensics must say M3 timeout." This is
  the strongest form of test available for an analysis tool, and it is only
  possible because the simulator is deterministic and labelled.

* **Robustness tests** run against deliberately hostile and malformed captures.
  Anything arriving over the air is attacker-controlled, so "does not crash on
  garbage" is a correctness requirement, not a nicety.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from airframe.pcap.anomaly import Severity, scan_capture
from airframe.pcap.assoc import Stage, analyse, analyse_file
from airframe.pcap.dissect import FrameKind, load_capture
from airframe.pcap.tshark_check import cross_check, tshark_available

REPO = Path(__file__).resolve().parents[2]
PCAPS = REPO / "data" / "pcaps"
MANIFEST = REPO / "data" / "corpus_manifest.json"


def _corpus() -> list[dict]:
    if not MANIFEST.exists():
        return []
    return json.loads(MANIFEST.read_text())["deterministic"]


def _one(scenario: str, fault: str) -> Path:
    """First corpus capture for a (scenario, fault) pair."""
    for entry in _corpus():
        if entry["scenario"] == scenario and entry["fault"] == fault:
            p = Path(entry["pcap"])
            if p.exists():
                return p
    pytest.skip(f"no corpus capture for {scenario}/{fault}; run scripts/build_corpus.py")


pytestmark = pytest.mark.skipif(not MANIFEST.exists(), reason="corpus not built")


# ---------------------------------------------------------------- dissection


class TestDissection:
    def test_healthy_wpa3_capture_has_the_full_frame_sequence(self) -> None:
        cap = load_capture(_one("wpa3", "NONE"))
        counts = cap.counts()

        assert counts["beacon"] >= 1
        assert counts["probe_request"] >= 1
        # WPA3 = SAE: four auth frames, not two.
        assert counts["sae_commit"] >= 2, "SAE Commit from both STA and AP"
        assert counts["sae_confirm"] >= 2, "SAE Confirm from both STA and AP"
        assert counts["assoc_request"] >= 1
        assert counts["assoc_response"] >= 1
        for m in ("eapol_m1", "eapol_m2", "eapol_m3", "eapol_m4"):
            assert counts[m] >= 1, f"{m} missing from a healthy handshake"

    def test_wpa2_uses_open_system_auth_not_sae(self) -> None:
        cap = load_capture(_one("wpa2", "NONE"))
        counts = cap.counts()
        assert counts["auth"] >= 2, "WPA2 uses Open System authentication"
        assert counts["sae_commit"] == 0, "WPA2 must not use SAE"

    def test_open_network_has_no_eapol_at_all(self) -> None:
        cap = load_capture(_one("open", "NONE"))
        assert not [f for f in cap if f.is_eapol], "an open network has no 4-way handshake"

    def test_rsn_akm_is_parsed_from_the_beacon(self) -> None:
        wpa3 = load_capture(_one("wpa3", "NONE"))
        wpa2 = load_capture(_one("wpa2", "NONE"))
        assert any(f.rsn_akm == "SAE" for f in wpa3), "WPA3 beacon must advertise SAE"
        assert any(f.rsn_akm == "PSK" for f in wpa2), "WPA2-PSK beacon must advertise PSK"

    def test_radio_metadata_is_present(self) -> None:
        cap = load_capture(_one("wpa2", "NONE"))
        assert cap.rssi_values, "radiotap RSSI was not parsed"
        assert all(-100 <= v <= -10 for v in cap.rssi_values)
        assert any(f.freq_mhz for f in cap), "channel frequency was not parsed"

    def test_frames_are_time_ordered(self) -> None:
        cap = load_capture(_one("wpa2", "NONE"))
        times = [f.time_s for f in cap]
        assert times == sorted(times), "frames must be in capture order"


# ---------------------------------------------------------------- forensics


class TestForensics:
    def test_healthy_session_is_reported_as_success(self) -> None:
        report = analyse_file(_one("wpa3", "NONE"))
        assert report.succeeded, report.report()
        assert report.stage_reached is Stage.DATA
        assert report.failed_at is None

    def test_m3_timeout_is_diagnosed_by_stage_and_reason_code(self) -> None:
        """The signature case: name the stage AND the reason."""
        report = analyse_file(_one("wpa2", "FOURWAY_M3_TIMEOUT"))

        assert not report.succeeded
        assert report.failed_at is Stage.ASSOCIATED, "failure is after association"
        assert report.reason_code == 15
        assert "M3" in report.verdict
        assert "timed out" in report.verdict.lower()
        # It must also blame the correct side. An M3 timeout is the AP's fault.
        assert "AP" in report.verdict

    def test_pmk_mismatch_is_distinguished_from_m3_timeout(self) -> None:
        """Same stage, different reason code, different owner.

        This is the discrimination the whole triage pipeline depends on: if the
        forensics cannot separate these two, no downstream layer can.
        """
        timeout = analyse_file(_one("wpa2", "FOURWAY_M3_TIMEOUT"))
        mismatch = analyse_file(_one("wpa2", "PMK_MISMATCH"))

        assert timeout.failed_at == mismatch.failed_at, "both fail in the handshake"
        assert timeout.reason_code == 15
        assert mismatch.reason_code == 23
        assert timeout.verdict != mismatch.verdict
        assert "passphrase" in mismatch.verdict.lower()

    def test_auth_timeout_is_diagnosed(self) -> None:
        report = analyse_file(_one("wpa2", "AUTH_TIMEOUT"))
        assert not report.succeeded
        assert "authentication" in report.verdict.lower()
        assert report.stage_reached.rank < Stage.ASSOCIATED.rank

    def test_assoc_reject_reports_the_status_code(self) -> None:
        report = analyse_file(_one("wpa2", "ASSOC_REJECT"))
        assert not report.succeeded
        assert report.status_code == 17
        assert "association" in report.verdict.lower()

    def test_scan_empty_reports_the_ap_was_never_heard(self) -> None:
        report = analyse_file(_one("wpa2", "SCAN_EMPTY"))
        assert not report.succeeded
        assert report.stage_reached is Stage.NOTHING
        assert "never heard" in report.verdict.lower()

    def test_dhcp_failure_is_correctly_invisible_to_the_radio_layer(self) -> None:
        """DHCP_NAK must look like radio success, because it IS radio success.

        The packet capture genuinely shows a healthy association: the failure is one
        layer up. A forensics tool that claimed to see a DHCP problem in an 802.11
        capture would be lying, and the verdict says so explicitly — this is what
        the log-correlation layer is for.
        """
        report = analyse_file(_one("wpa2", "DHCP_NAK"))
        assert report.stage_reached in (Stage.KEYED, Stage.DATA)
        assert report.reason_code != 15

    def test_stage_timings_are_extracted(self) -> None:
        report = analyse_file(_one("wpa2", "NONE"))
        names = {t.name for t in report.timings}
        assert "authentication" in names
        assert "association" in names
        assert "4-way handshake" in names
        assert all(t.duration_ms >= 0 for t in report.timings)

    def test_report_is_human_readable_and_complete(self) -> None:
        text = analyse_file(_one("wpa2", "FOURWAY_M3_TIMEOUT")).report()
        for section in ("Capture", "Stage reached", "VERDICT", "Reason code", "Evidence"):
            assert section in text, f"report is missing the {section!r} section"

    @pytest.mark.parametrize("scenario", ["wpa2", "wpa3", "open", "enterprise", "legacy"])
    def test_every_healthy_scenario_is_reported_as_success(self, scenario: str) -> None:
        """Positive coverage across scenarios.

        Without this, a detector that reports 'failure' unconditionally would pass
        every fault test in this file — which is exactly the bug found in
        BUILD_JOURNAL #11.
        """
        report = analyse_file(_one(scenario, "NONE"))
        assert report.succeeded, f"{scenario}: {report.verdict}"


# ---------------------------------------------------------------- anomalies


class TestAnomalies:
    def test_healthy_capture_raises_no_critical_anomalies(self) -> None:
        cap = load_capture(_one("wpa2", "NONE"))
        critical = [a for a in scan_capture(cap) if a.severity is Severity.CRITICAL]
        assert not critical, f"false positives on a healthy capture: {critical}"

    def test_m3_timeout_raises_eapol_retransmission(self) -> None:
        cap = load_capture(_one("wpa2", "FOURWAY_M3_TIMEOUT"))
        detectors = {a.detector for a in scan_capture(cap)}
        assert "eapol_retransmission" in detectors
        assert "incomplete_handshake" in detectors

    def test_channel_busy_raises_excessive_retries(self) -> None:
        cap = load_capture(_one("wpa2", "CHANNEL_BUSY"))
        found = [a for a in scan_capture(cap) if a.detector == "excessive_retries"]
        assert found, f"retry rate was {cap.retry_rate:.1%}, expected an anomaly"
        assert found[0].value and found[0].value > 0.20

    def test_low_rssi_raises_weak_signal(self) -> None:
        cap = load_capture(_one("wpa2", "LOW_RSSI"))
        detectors = {a.detector for a in scan_capture(cap)}
        assert "weak_signal" in detectors or "rssi_collapse" in detectors

    def test_deauth_flood_is_detected(self) -> None:
        cap = load_capture(PCAPS / "synth_deauth_flood.pcap")
        found = [a for a in scan_capture(cap) if a.detector == "deauth_flood"]
        assert found
        assert found[0].severity is Severity.CRITICAL

    def test_krack_replay_is_detected_and_explained(self) -> None:
        cap = load_capture(PCAPS / "synth_krack_m3_replay.pcap")
        found = [a for a in scan_capture(cap) if a.detector == "key_reinstallation"]
        assert found, "KRACK-style M3 replay was not detected"
        # The distinguishing evidence is the increasing replay counter.
        assert "replay counter" in found[0].detail.lower()

    def test_unprotected_management_is_flagged_on_wpa2_only(self) -> None:
        wpa2 = scan_capture(load_capture(PCAPS / "synth_deauth_flood.pcap"))
        assert any(a.detector == "unprotected_management_frames" for a in wpa2), (
            "a WPA2 network with unprotected deauths should be flagged"
        )

    def test_every_anomaly_carries_an_explanation(self) -> None:
        """An anomaly without a detail string is not actionable."""
        for name in ("synth_deauth_flood", "synth_krack_m3_replay"):
            for a in scan_capture(load_capture(PCAPS / f"{name}.pcap")):
                assert a.summary, f"{a.detector} has no summary"
                assert a.detail, f"{a.detector} has no detail explaining what to do"


# ---------------------------------------------------------------- robustness


class TestRobustness:
    """Malformed and hostile input must not crash the analysis.

    Everything here is attacker-controllable in the real world.
    """

    @pytest.mark.parametrize(
        "name",
        ["synth_truncated_ie", "synth_hidden_ssid", "synth_bogus_rsn",
         "synth_long_ie_chain", "synth_mixed_hostile", "synth_clean_beacon"],
    )
    def test_malformed_capture_does_not_crash_any_layer(self, name: str) -> None:
        path = PCAPS / f"{name}.pcap"
        if not path.exists():
            pytest.skip(f"{name} not generated")
        cap = load_capture(path)          # dissection
        report = analyse(cap)             # forensics
        anomalies = scan_capture(cap)     # detectors
        assert report.verdict, "even a garbage capture must produce a verdict"
        assert isinstance(anomalies, list)

    def test_truncated_information_element_is_survived(self) -> None:
        """An IE whose length field lies must not walk off the end of the buffer."""
        cap = load_capture(PCAPS / "synth_truncated_ie.pcap")
        assert len(cap) == 1
        assert cap.frames[0].kind is FrameKind.BEACON

    def test_long_ie_chain_terminates(self) -> None:
        """Proves the IE walker has a loop guard rather than spinning forever."""
        cap = load_capture(PCAPS / "synth_long_ie_chain.pcap")
        frame = cap.frames[0]
        assert len(frame.elements) <= 64, "the IE walk must be bounded"

    def test_empty_capture_is_handled(self, tmp_path: Path) -> None:
        from scapy.all import wrpcap

        empty = tmp_path / "empty.pcap"
        wrpcap(str(empty), [])
        cap = load_capture(empty)
        assert len(cap) == 0
        assert analyse(cap).verdict, "an empty capture still needs a verdict"

    def test_missing_file_raises_a_clear_error(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_capture("/nonexistent/path/to.pcap")


# ---------------------------------------------------------------- oracle


class TestTsharkOracle:
    """Cross-validate our dissector against an independent implementation.

    Skipped, loudly, when tshark is absent — a cross-check whose oracle is missing
    must never report success.
    """

    @pytest.mark.skipif(not tshark_available(), reason="tshark not installed")
    @pytest.mark.parametrize(
        "scenario,fault",
        [("wpa2", "NONE"), ("wpa3", "NONE"), ("open", "NONE"),
         ("wpa2", "FOURWAY_M3_TIMEOUT"), ("wpa2", "PMK_MISMATCH"),
         ("wpa2", "ASSOC_REJECT"), ("wifi6e", "NONE")],
    )
    def test_our_dissection_agrees_with_tshark(self, scenario: str, fault: str) -> None:
        result = cross_check(load_capture(_one(scenario, fault)))
        assert result.frame_count_ours == result.frame_count_tshark, (
            f"frame count differs: {result.report()}"
        )
        assert not result.disagreements, result.report()

    @pytest.mark.skipif(not tshark_available(), reason="tshark not installed")
    def test_simulator_emits_no_malformed_frames(self) -> None:
        """The DUT must produce spec-correct frames.

        This is the assertion that would have caught BUILD_JOURNAL #5 (empty SAE
        bodies) immediately instead of after it was noticed by eye.
        """
        for scenario in ("wpa2", "wpa3", "open", "enterprise", "wifi6e", "legacy"):
            result = cross_check(load_capture(_one(scenario, "NONE")))
            assert not result.malformed_frames, (
                f"{scenario}: tshark flags frames {result.malformed_frames} as malformed"
            )
