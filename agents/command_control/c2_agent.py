import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

AGENT_NAME = "Command & Control Agent"
KILL_CHAIN_STAGE = "Command and Control"

OUTPUT_PATH = Path("output/command_control.json")
CONFIDENCE_SCALE = 100

MIN_CONNECTIONS = 8
MAX_INTERVAL_CV = 0.20
MAX_BYTE_CV = 0.10

TRUSTED_DESTINATIONS = []

MITRE_BY_PORT = {
    53: ("T1071.004", "Application Layer Protocol: DNS"),
    80: ("T1071.001", "Application Layer Protocol: Web Protocols"),
    443: ("T1573", "Encrypted Channel"),
    8080: ("T1071.001", "Application Layer Protocol: Web Protocols"),
}
MITRE_DEFAULT = ("T1071", "Application Layer Protocol")


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

    return build_finding(key, events, gaps, interval_cv, byte_cv, outbound, score)


def build_finding(key, events, gaps, interval_cv, byte_cv, outbound, score):
    source, destination, port = key
    mean_gap = statistics.mean(gaps)
    span_minutes = (events[-1]["timestamp"] - events[0]["timestamp"]) / 60
    technique, technique_name = MITRE_BY_PORT.get(port, MITRE_DEFAULT)
    high_confidence = score >= 0.80

    evidence = [
        f"Source host: {source}",
        f"Destination: {destination}:{port}",
        f"{len(events)} connections over {span_minutes:.1f} minutes",
        f"Mean interval {mean_gap:.1f}s, varying by only {interval_cv * 100:.1f}% "
        f"(normal user traffic varies far more)",
    ]
    if byte_cv is not None and byte_cv <= MAX_BYTE_CV:
        evidence.append(
            f"Outbound payload near constant at "
            f"{statistics.mean(outbound):.0f} bytes per connection"
        )
    service = events[0].get("service", "-")
    if service and service != "-":
        evidence.append(f"Service identified as {service}")

    if high_confidence:
        action = (
            f"Isolate {source} and block outbound traffic to {destination}. "
            f"Review the host for persistence mechanisms."
        )
    else:
        action = (
            f"Investigate outbound traffic from {source} to {destination} and "
            f"confirm whether a scheduled process accounts for it."
        )

    return {
        "agent": AGENT_NAME,
        "stage": KILL_CHAIN_STAGE,
        "timestamp": datetime.fromtimestamp(
            events[-1]["timestamp"], tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "severity": "High" if high_confidence else "Medium",
        "mitre_technique": technique,
        "mitre_name": technique_name,
        "description": (
            f"Host {source} is contacting {destination}:{port} at regular "
            f"intervals, consistent with an automated command and control channel."
        ),
        "evidence": evidence,
        "confidence": to_confidence(score),
        "recommended_action": action,
    }


def to_confidence(score):
    if CONFIDENCE_SCALE == 100:
        return round(score * 100)
    return round(score, 2)


def analyse(events, **thresholds):
    findings = []
    for key, group in group_by_destination(events).items():
        finding = detect_beaconing(key, group, **thresholds)
        if finding:
            findings.append(finding)
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings


def save_findings(findings, path=OUTPUT_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "agent": AGENT_NAME,
        "stage": KILL_CHAIN_STAGE,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finding_count": len(findings),
        "findings": findings,
    }
    with open(path, "w") as handle:
        json.dump(payload, handle, indent=2)
    return path


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/beacon_60s.log"

    from agents.command_control.parsers import load_events

    events = load_events(log_path)
    findings = analyse(events)
    output = save_findings(findings)

    print(f"Analysed {len(events)} connections from {log_path}")
    print(f"{len(findings)} finding(s) written to {output}")
    for finding in findings:
        print(f"  [{finding['severity']}] {finding['description']}")


if __name__ == "__main__":
    main()