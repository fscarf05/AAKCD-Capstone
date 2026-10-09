import json
from pathlib import Path

from agents.command_control.c2_agent import analyse, save_findings
from agents.command_control.parsers import load_events

FIXTURES = Path(__file__).parent / "fixtures"

SCHEMA_FIELDS = [
    "agent", "stage", "timestamp", "severity", "mitre_technique",
    "mitre_name", "description", "evidence", "confidence",
    "recommended_action",
]


def run(filename, **thresholds):
    return analyse(load_events(FIXTURES / filename), **thresholds)


def test_clean_beacon_is_detected():
    findings = run("beacon_60s.log")
    assert len(findings) == 1
    assert "10.0.0.15" in findings[0]["description"]
    assert "203.0.113.44" in findings[0]["description"]


def test_normal_browsing_produces_no_findings():
    assert run("normal_browsing.log") == []


def test_beacon_is_high_severity():
    finding = run("beacon_60s.log")[0]
    assert finding["severity"] == "High"
    assert finding["confidence"] >= 80


def test_too_few_connections_are_ignored():
    events = load_events(FIXTURES / "beacon_60s.log")[:5]
    assert analyse(events) == []


def test_finding_matches_shared_schema():
    finding = run("beacon_60s.log")[0]
    for field in SCHEMA_FIELDS:
        assert field in finding, f"missing schema field: {field}"
    assert isinstance(finding["evidence"], list)
    assert all(isinstance(item, str) for item in finding["evidence"])
    assert finding["severity"] in ("Low", "Medium", "High", "Critical")
    assert finding["stage"] == "Command and Control"


def test_timestamp_is_iso_utc():
    finding = run("beacon_60s.log")[0]
    assert finding["timestamp"].endswith("Z")
    assert len(finding["timestamp"]) == 20


def test_https_beacon_maps_to_encrypted_channel():
    finding = run("beacon_60s.log")[0]
    assert finding["mitre_technique"] == "T1573"
    assert finding["mitre_name"] == "Encrypted Channel"


def test_evidence_reports_the_interval():
    evidence = " ".join(run("beacon_60s.log")[0]["evidence"])
    assert "40 connections" in evidence
    assert "203.0.113.44:443" in evidence


def test_jittery_beacon_missed_at_default_thresholds():
    assert run("beacon_jittery.log") == []


def test_jittery_beacon_caught_when_thresholds_loosened():
    findings = run("beacon_jittery.log", max_interval_cv=0.40)
    assert len(findings) == 1
    assert "198.51.100.7" in findings[0]["description"]


def test_loosened_thresholds_still_reject_normal_browsing():
    assert run("normal_browsing.log", max_interval_cv=0.40) == []


def test_save_findings_writes_valid_json(tmp_path):
    findings = run("beacon_60s.log")
    output = save_findings(findings, tmp_path / "command_control.json")

    with open(output) as handle:
        payload = json.load(handle)

    assert payload["stage"] == "Command and Control"
    assert payload["finding_count"] == 1
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["mitre_technique"] == "T1573"


def test_save_findings_handles_empty_results(tmp_path):
    output = save_findings([], tmp_path / "command_control.json")

    with open(output) as handle:
        payload = json.load(handle)

    assert payload["finding_count"] == 0
    assert payload["findings"] == []
