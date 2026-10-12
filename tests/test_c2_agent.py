import json
from pathlib import Path

from agents.command_control.c2_agent import analyse, save_findings
from agents.command_control.parsers import load_events

FIXTURES = Path(__file__).parent / "fixtures"

REQUIRED_FIELDS = [
    "agent", "stage", "timestamp", "severity", "confidence",
    "mitre_technique_id", "mitre_technique", "description",
    "evidence", "recommended_actions",
]


def run(filename, **thresholds):
    return analyse(load_events(FIXTURES / filename), **thresholds)


def test_clean_beacon_is_detected():
    alerts = run("beacon_60s.log")
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.15"
    assert alerts[0]["evidence"]["destination_ip"] == "203.0.113.44"


def test_normal_browsing_produces_no_alerts():
    assert run("normal_browsing.log") == []


def test_beacon_is_high_severity_and_high_confidence():
    alert = run("beacon_60s.log")[0]
    assert alert["severity"] == "HIGH"
    assert alert["confidence"] == "high"


def test_too_few_connections_are_ignored():
    events = load_events(FIXTURES / "beacon_60s.log")[:5]
    assert analyse(events) == []


def test_alert_matches_shared_schema():
    alert = run("beacon_60s.log")[0]
    for field in REQUIRED_FIELDS:
        assert field in alert, f"missing schema field: {field}"
    assert alert["agent"] == "command_control"
    assert alert["stage"] == "command_control"
    assert alert["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert alert["confidence"] in ("low", "medium", "high")


def test_evidence_is_a_structured_object():
    evidence = run("beacon_60s.log")[0]["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["connection_count"] == 40
    assert evidence["destination_port"] == 443
    assert 58 <= evidence["mean_interval_seconds"] <= 62
    assert evidence["interval_cv"] < 0.05


def test_recommended_actions_is_an_ordered_list():
    actions = run("beacon_60s.log")[0]["recommended_actions"]
    assert isinstance(actions, list)
    assert len(actions) >= 1
    assert all(isinstance(action, str) for action in actions)
    assert "Isolate" in actions[0]


def test_timestamp_is_iso_utc():
    alert = run("beacon_60s.log")[0]
    assert alert["timestamp"].endswith("Z")
    assert len(alert["timestamp"]) == 20


def test_mitre_mapping_is_complete():
    alert = run("beacon_60s.log")[0]
    assert alert["mitre_tactic_id"] == "TA0011"
    assert alert["mitre_tactic"] == "Command and Control"
    assert alert["mitre_technique_id"] == "T1573"
    assert alert["mitre_technique"] == "Encrypted Channel"


def test_no_empty_ai_fields_in_output():
    alert = run("beacon_60s.log")[0]
    assert "ai_status" not in alert
    assert "ai_summary" not in alert


def test_jittery_beacon_missed_at_default_thresholds():
    assert run("beacon_jittery.log") == []


def test_jittery_beacon_caught_when_thresholds_loosened():
    alerts = run("beacon_jittery.log", max_interval_cv=0.40)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["destination_ip"] == "198.51.100.7"


def test_loosened_thresholds_still_reject_normal_browsing():
    assert run("normal_browsing.log", max_interval_cv=0.40) == []


def test_save_findings_writes_valid_json(tmp_path):
    alerts = run("beacon_60s.log")
    output = save_findings(alerts, tmp_path / "command_control.json")

    with open(output) as handle:
        payload = json.load(handle)

    assert payload["agent"] == "command_control"
    assert payload["alert_count"] == 1
    assert payload["alerts"][0]["mitre_technique_id"] == "T1573"
    assert isinstance(payload["alerts"][0]["evidence"], dict)


def test_save_findings_handles_empty_results(tmp_path):
    output = save_findings([], tmp_path / "command_control.json")

    with open(output) as handle:
        payload = json.load(handle)

    assert payload["alert_count"] == 0
    assert payload["alerts"] == []