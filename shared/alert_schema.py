"""
AAKCD shared alert schema.

Every agent should build its alerts using the Alert dataclass below, then
call .to_dict() before writing to its output file or sending to Wazuh.
This keeps every agent's JSON output byte-for-byte consistent in field
names and casing, which the json_output.py docstring didn't guarantee
before (the old alert_schema.json and alert_schema.py here disagreed
with each other on field names, severity casing, and confidence type —
this version is the single source of truth, replacing both).

See alert_schema.json in this folder for field-by-field documentation
and examples.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal, Optional

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Confidence = Literal["low", "medium", "high"]


@dataclass
class Alert:
    agent: str
    stage: str
    severity: Severity
    confidence: Confidence
    mitre_technique_id: str
    mitre_technique: str
    description: str
    evidence: dict
    recommended_actions: list[str]

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    mitre_tactic_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    source_ip: Optional[str] = None

    ai_status: Optional[str] = None            # "ok" | "unavailable"
    ai_summary: Optional[str] = None
    ai_recommended_actions: Optional[list[str]] = None

    def __post_init__(self):
        if self.severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"severity must be LOW/MEDIUM/HIGH/CRITICAL, got {self.severity!r}")
        if self.confidence not in ("low", "medium", "high"):
            raise ValueError(f"confidence must be low/medium/high, got {self.confidence!r}")
        if not self.recommended_actions:
            raise ValueError("recommended_actions must have at least one item")

    def to_dict(self) -> dict:
        # drop optional fields that were never set, so e.g. an agent with
        # no AI step doesn't write out a bunch of nulls
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


if __name__ == "__main__":
    # Example: how a recon-style alert would be built with this schema
    example = Alert(
        agent="recon",
        stage="reconnaissance",
        severity="HIGH",
        confidence="high",
        mitre_tactic_id="TA0043",
        mitre_tactic="Reconnaissance",
        mitre_technique_id="T1595",
        mitre_technique="Active Scanning",
        source_ip="192.168.221.129",
        description="192.168.221.129 probed 100 distinct ports on 192.168.221.130 within 60 seconds.",
        evidence={"scan_type": "vertical", "distinct_targets": 100, "incomplete_connection_ratio": 1.0},
        recommended_actions=[
            "Confirm whether 192.168.221.129 is an authorised scanner.",
            "If unauthorised, block it at the firewall.",
        ],
        ai_status="ok",
        ai_summary="This is a vertical port scan, likely reconnaissance ahead of exploitation.",
    )
    import json
    print(json.dumps(example.to_dict(), indent=2))
