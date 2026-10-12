import json
from pathlib import Path
from .alert_schema import Alert

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_FILE = LOG_DIR / "installation_alerts.jsonl"

TECHNIQUES = {
    "T1547.001": ("Registry Run Keys / Startup Folder", "TA0003", "Persistence"),
    "T1053.005": ("Scheduled Task", "TA0003", "Persistence"),
    "T1543.003": ("Windows Service", "TA0003", "Persistence"),
}

def build_alert(host: str, technique_id: str, entry: dict, severity: str, confidence: str) -> dict:
    name, tactic_id, tactic = TECHNIQUES.get(technique_id, ("Unknown technique", None, None))
    # Keep cross-agent evidence keys exact. For installation persistence, expose a
    # full path as file_path where available; preserve the complete raw entry too.
    evidence = {"host": host, "baseline_comparison": "new_entry", "entry": entry}
    candidate_path = entry.get("path") or entry.get("command")
    if candidate_path:
        evidence["file_path"] = str(candidate_path)
    # A scheduled task's run-as account is not proof of a newly created account,
    # so do not label it as evidence["username"] unless account creation is detected.

    alert = Alert(
        agent="installation",
        stage="installation",
        severity=severity,
        confidence=confidence,
        mitre_tactic_id=tactic_id,
        mitre_tactic=tactic,
        mitre_technique_id=technique_id,
        mitre_technique=name,
        source_ip=None,
        description=f"A persistence entry not present in the saved baseline was detected on host {host}.",
        evidence=evidence,
        recommended_actions=[
            "Validate whether this persistence change was authorised.",
            "Inspect the referenced executable and related host events.",
            "If confirmed malicious, follow the incident response procedure.",
        ],
    )
    return alert.to_dict()

def send_alert(alert: dict) -> None:
    """Append one schema-compliant JSON object per line, then print it."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert, separators=(",", ":")) + "\n")
    print(json.dumps(alert, indent=2))
    print(f"[+] Alert appended to {LOG_FILE}")
