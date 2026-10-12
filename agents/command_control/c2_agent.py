import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

AGENT_NAME = "command_control"
KILL_CHAIN_STAGE = "command_control"

OUTPUT_PATH = Path("output/command_control.json")

MIN_CONNECTIONS = 8
MAX_INTERVAL_CV = 0.20
MAX_BYTE_CV = 0.10

HIGH_SCORE = 0.80
MEDIUM_SCORE = 0.65

TRUSTED_DESTINATIONS = []

MITRE_TACTIC_ID = "TA0011"
MITRE_TACTIC = "Command and Control"

MITRE_BY_PORT = {
    53: ("T1071.004", "Application Layer Protocol: DNS"),
    80: ("T1071.001", "Application Layer Protocol: Web Protocols"),
    443: ("T1573", "Encrypted Channel"),
    8080: ("T1071.001", "Application Layer Protocol: Web Protocols"),
}
MITRE_DEFAULT = ("T1071", "Application Layer Protocol")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def group_by_destination(events):
    groups = defaultdict(list)
    for event in events:
        source = event.get("source_ip")
        destination = event.get("destination_ip")
        port = event.get("destination_port")
        timestamp = event.get("timestamp")

        if not source or not destination or port is None or timestamp is None:
            continue
        if destination in TRUSTED_DESTINATIONS:
            continue

        groups[(source, destination, int(port))].append(event)
    return groups


def coefficient_of_variation(values):
    if len(values) < 2:
        return None
    mean = statistics.mean(values)
    if mean == 0:
        return None
    return statistics.pstdev(values) / mean


def detect_beaconing(key, events,
                     min_connections=MIN_CONNECTIONS,
                     max_interval_cv=MAX_INTERVAL_CV,
                     max_byte_cv=MAX_BYTE_CV):
    if len(events) < min_connections:
        return None

    events.sort(key=lambda e: e["timestamp"])
    gaps = [
        later["timestamp"] - earlier["timestamp"]
        for earlier, later in zip(events, events[1:])
    ]
    gaps = [gap for gap in gaps if gap > 0]

    interval_cv = coefficient_of_variation(gaps)
    if interval_cv is None or interval_cv > max_interval_cv:
        return None

    outbound = [event.get("bytes_out", 0) for event in events]
    byte_cv = coefficient_of_variation(outbound)

    score = 0.50 + (1 - interval_cv / max_interval_cv) * 0.30
    if byte_cv is not None and byte_cv <= max_byte_cv:
        score += 0.15
    if len(events) >= min_connections * 3:
        score += 0.05
    score = min(score, 0.98)

    return build_alert(key, events, gaps, interval_cv, byte_cv, outbound, score)


def build_alert(key, events, gaps, interval_cv, byte_cv, outbound, score):
    source, destination, port = key
    mean_gap = statistics.mean(gaps)
    span_minutes = (events[-1]["timestamp"] - events[0]["timestamp"]) / 60
    technique_id, technique = MITRE_BY_PORT.get(port, MITRE_DEFAULT)

    evidence = {
        "destination_ip": destination,
        "destination_port": port,
        "connection_count": len(events),
        "span_minutes": round(span_minutes, 1),
        "mean_interval_seconds": round(mean_gap, 1),
        "interval_cv": round(interval_cv, 3),
        "mean_bytes_out": round(statistics.mean(outbound), 1),
    }
    if byte_cv is not None:
        evidence["byte_cv"] = round(byte_cv, 3)
    service = events[0].get("service", "-")
    if service and service != "-":
        evidence["service"] = service

    if score >= HIGH_SCORE:
        actions = [
            f"Isolate {source} from the network.",
            f"Block outbound traffic to {destination} at the firewall.",
            f"Review {source} for persistence mechanisms, since an active command "
            f"and control channel implies the installation stage already succeeded.",
        ]
    else:
        actions = [
            f"Investigate outbound traffic from {source} to {destination}.",
            "Confirm whether a scheduled process or update service accounts for "
            "the regular interval.",
            f"If unexplained, block outbound traffic to {destination}.",
        ]

    return {
        "agent": AGENT_NAME,
        "stage": KILL_CHAIN_STAGE,
        "timestamp": datetime.fromtimestamp(
            events[-1]["timestamp"], tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "severity": "HIGH" if score >= HIGH_SCORE else "MEDIUM",
        "confidence": to_confidence(score),
        "mitre_tactic_id": MITRE_TACTIC_ID,
        "mitre_tactic": MITRE_TACTIC,
        "mitre_technique_id": technique_id,
        "mitre_technique": technique,
        "source_ip": source,
        "description": (
            f"{source} contacted {destination}:{port} {len(events)} times at a "
            f"near-constant {mean_gap:.1f} second interval, varying by only "
            f"{interval_cv * 100:.1f} percent. Regularity of this kind indicates "
            f"an automated command and control channel rather than user activity."
        ),
        "evidence": evidence,
        "recommended_actions": actions,
    }


def to_confidence(score):
    if score >= HIGH_SCORE:
        return "high"
    if score >= MEDIUM_SCORE:
        return "medium"
    return "low"


def analyse(events, **thresholds):
    alerts = []
    for key, group in group_by_destination(events).items():
        alert = detect_beaconing(key, group, **thresholds)
        if alert:
            alerts.append(alert)
    alerts.sort(
        key=lambda a: (SEVERITY_RANK[a["severity"]], CONFIDENCE_RANK[a["confidence"]]),
        reverse=True,
    )
    return alerts


def save_findings(alerts, path=OUTPUT_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "agent": AGENT_NAME,
        "stage": KILL_CHAIN_STAGE,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    with open(path, "w") as handle:
        json.dump(payload, handle, indent=2)
    return path


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/beacon_60s.log"

    from agents.command_control.parsers import load_events

    events = load_events(log_path)
    alerts = analyse(events)
    output = save_findings(alerts)

    print(f"Analysed {len(events)} connections from {log_path}")
    print(f"{len(alerts)} alert(s) written to {output}")
    for alert in alerts:
        print(f"  [{alert['severity']}/{alert['confidence']}] {alert['description']}")


if __name__ == "__main__":
    main()