# correlator.py
import json
import os
from datetime import datetime, timedelta, timezone

TIME_WINDOW_MINUTES = 30
INCIDENTS_FILE = "incidents.json"
CLOSED_INCIDENTS_FILE = "closed_incidents.json"
RESPONSES_FILE = "responses.json"
COUNTER_FILE = "incident_counter.json"

def _parse_time(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def load_incidents():
    if os.path.exists(INCIDENTS_FILE):
        with open(INCIDENTS_FILE) as f:
            return json.load(f)
    return []

def save_incidents(incidents):
    with open(INCIDENTS_FILE, "w") as f:
        json.dump(incidents, f, indent=2)

def _next_incident_id():
    if os.path.exists(COUNTER_FILE):
        with open(COUNTER_FILE) as f:
            n = json.load(f)["next_id"]
    else:
        n = 1
    with open(COUNTER_FILE, "w") as f:
        json.dump({"next_id": n + 1}, f)
    return n

def correlate(new_alerts, incidents):
    """
    Matches new_alerts against the existing (persisted) incidents list,
    rather than rebuilding from scratch each poll cycle. Returns the
    updated incidents list, plus 'events': one (incident, alert) pair
    per new alert processed this round, used for response decisions.
    """
    events = []

    for alert in new_alerts:
        alert_time = _parse_time(alert["timestamp"])
        matched = None

        for incident in incidents:
            if alert["identifier_value"] != incident["identifier_value"]:
                continue
            last_time = _parse_time(incident["alerts"][-1]["timestamp"])
            if alert_time - last_time <= timedelta(minutes=TIME_WINDOW_MINUTES):
                matched = incident
                break

        if matched:
            matched["alerts"].append(alert)
            events.append((matched, alert))
        else:
            new_incident = {
                "id": _next_incident_id(),
