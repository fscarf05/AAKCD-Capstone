import json
from pathlib import Path

from agents.command_control.c2_agent import analyse
from agents.command_control.enrichment import (
    GeminiClient,
    build_prompt,
    enrich,
    parse_response,
)
from agents.command_control.parsers import load_events

FIXTURES = Path(__file__).parent / "fixtures"


class FakeClient:

    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.prompts = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        if self.error:
            raise self.error
        return self.response


GOOD_RESPONSE = json.dumps({
    "summary": "The host is checking in with an external server on a fixed "
               "timer, which is characteristic of malware maintaining a "
               "command channel.",
    "actions": [
        "Isolate the host from the network.",
        "Block the destination at the perimeter firewall.",
    ],
})


def one_alert():
    return analyse(load_events(FIXTURES / "beacon_60s.log"))[0]


def test_successful_enrichment_sets_all_three_fields():
    alert = enrich(one_alert(), FakeClient(response=GOOD_RESPONSE))
    assert alert["ai_status"] == "ok"
    assert "command channel" in alert["ai_summary"]
    assert len(alert["ai_recommended_actions"]) == 2


def test_enrichment_does_not_overwrite_rule_based_output():
    alert = one_alert()
    original_description = alert["description"]
    original_actions = list(alert["recommended_actions"])

    enrich(alert, FakeClient(response=GOOD_RESPONSE))

    assert alert["description"] == original_description
    assert alert["recommended_actions"] == original_actions


def test_api_failure_marks_unavailable_without_crashing():
    alert = enrich(one_alert(), FakeClient(error=OSError("connection refused")))
    assert alert["ai_status"] == "unavailable"
    assert "ai_summary" not in alert
    assert alert["severity"] == "HIGH"
    assert alert["description"]


def test_malformed_response_marks_unavailable():
    alert = enrich(one_alert(), FakeClient(response="not json at all"))
    assert alert["ai_status"] == "unavailable"


def test_response_missing_actions_marks_unavailable():
    alert = enrich(one_alert(), FakeClient(response='{"summary": "something"}'))
    assert alert["ai_status"] == "unavailable"


def test_markdown_fenced_response_is_parsed():
    fenced = f"```json\n{GOOD_RESPONSE}\n```"
    summary, actions = parse_response(fenced)
    assert "command channel" in summary
    assert len(actions) == 2


def test_prompt_contains_the_evidence():
    client = FakeClient(response=GOOD_RESPONSE)
    enrich(one_alert(), client)
    prompt = client.prompts[0]
    assert "203.0.113.44" in prompt
    assert "connection_count: 40" in prompt
    assert "T1573" in prompt


def test_ai_is_off_by_default():
    alerts = analyse(load_events(FIXTURES / "beacon_60s.log"))
    assert "ai_status" not in alerts[0]


def test_analyse_with_ai_enriches_every_alert():
    alerts = analyse(
        load_events(FIXTURES / "beacon_60s.log"),
        use_ai=True,
        ai_client=FakeClient(response=GOOD_RESPONSE),
    )
    assert all(alert["ai_status"] == "ok" for alert in alerts)


def test_client_without_key_reports_unavailable():
    client = GeminiClient(api_key=None)
    if not client.available():
        alert = enrich(one_alert(), client)
        assert alert["ai_status"] == "unavailable"
