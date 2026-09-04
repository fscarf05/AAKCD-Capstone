import json
from collections import defaultdict
 
AGENT_NAME = "command_control"
KILL_CHAIN_PHASE = "Command and Control"
 
MIN_CONNECTIONS = 6
TRUSTED_DESTINATIONS = []
 
 
def load_events(path):
    events = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
 
 
def group_by_destination(events):
    groups = defaultdict(list)
    for event in events:
        source = event.get("source_ip")
        destination = event.get("destination_ip")
        if not source or not destination:
            continue
        if destination in TRUSTED_DESTINATIONS:
            continue
        groups[(source, destination)].append(event)
    return groups
 
 
def detect_repeated_contact(key, events):
    if len(events) < MIN_CONNECTIONS:
        return None
    source, destination = key
    return {
        "agent": AGENT_NAME,
        "kill_chain_phase": KILL_CHAIN_PHASE,
        "mitre_technique": "T1071",
        "source_ip": source,
        "destination_ip": destination,
        "description": "Repeated outbound connections to a single destination",
        "connection_count": len(events),
    }
 
 
def analyse(events):
    findings = []
    for key, group in group_by_destination(events).items():
        finding = detect_repeated_contact(key, group)
        if finding:
            findings.append(finding)
    return findings
 
 
def save_findings(findings, path):
    with open(path, "w") as f:
        json.dump({"agent": AGENT_NAME, "findings": findings}, f, indent=2)
 
 
def main():
    events = load_events("data/sample_logs.json")
    findings = analyse(events)
    save_findings(findings, "output/findings.json")
    print(len(findings), "findings")
 
 
if __name__ == "__main__":
    main()