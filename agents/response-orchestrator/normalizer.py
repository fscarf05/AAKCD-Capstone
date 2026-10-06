# normalizer.py

def _confidence_bucket(value):
    if value is None:
        return "low"
    if value >= 0.75:
        return "high"
    elif value >= 0.4:
        return "medium"
    else:
        return "low"

def normalize(alert):
    return {
        "source_agent": alert.get("agent", "unknown"),
        "kill_chain_stage": alert.get("kill_chain_stage", "unknown"),
        "mitre_technique": alert.get("mitre_technique", "unknown"),
        "summary": alert.get("activity", "No description provided"),
        "confidence": _confidence_bucket(alert.get("confidence")),
        "identifier_type": "source_ip",
        "identifier_value": alert.get("source_ip", "unknown"),
        "timestamp": alert.get("timestamp"),
    }
