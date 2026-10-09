# poller.py
import json
import os
import time
from datetime import datetime, timezone
from mock_alerts import MOCK_ALERTS
from normalizer import normalize
from correlator import (
    correlate, load_incidents, save_incidents,
    close_expired, archive_closed,
    decide_response, archive_response,
)

CHECKPOINT_FILE = "checkpoint.json"

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE) as f:
            return json.load(f)["last_seen"]
    return "1970-01-01T00:00:00Z"

def save_checkpoint(timestamp):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({"last_seen": timestamp}, f)

def get_new_alerts(last_checkpoint):
    new = [a for a in MOCK_ALERTS if a["timestamp"] > last_checkpoint]
    new.sort(key=lambda a: a["timestamp"])
    return new

def poll_once():
    last_checkpoint = load_checkpoint()
    new_alerts = get_new_alerts(last_checkpoint)

    if not new_alerts:
        print(f"[{datetime.now(timezone.utc).isoformat()}] No new alerts.")
        return

    normalized = [normalize(a) for a in new_alerts]

    incidents = load_incidents()
    incidents, events = correlate(normalized, incidents)

    for incident, alert in events:
        action = decide_response(incident, alert)
        if action:
            print(action)
            archive_response(action)

    incidents, newly_closed = close_expired(incidents)
    archive_closed(newly_closed)
    save_incidents(incidents)

    still_open_ids = {incident["id"] for incident in incidents}

    printed = set()
    for incident, _ in events:
        key = incident["identifier_value"]
        if key in printed:
            continue
        printed.add(key)

        if incident["id"] not in still_open_ids:
            print(f"\n=== incident #{incident['id']} [{incident['identifier_type']}={incident['identifier_value']}] "
                  f"CLOSED (already {len(incident['alerts'])} alert(s), aged out immediately this cycle) ===")
            continue

        label = "CORRELATED INCIDENT" if incident["correlated"] else "standalone alert"
        print(f"\n=== {label} #{incident['id']} [{incident['identifier_type']}={incident['identifier_value']}] "
              f"severity={incident['severity']} (alerts so far: {len(incident['alerts'])}, "
              f"responded stages: {incident['responded_stages']}) ===")
        for a in incident["alerts"]:
            print(f"  - {a['source_agent']}: {a['summary']} (confidence: {a['confidence']})")

    save_checkpoint(new_alerts[-1]["timestamp"])

if __name__ == "__main__":
    while True:
        poll_once()
        time.sleep(15)
