"""Turn a Finding into an alert using the AAKCD shared alert schema (alert_schema.py)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from alert_schema import Alert
from detector import Finding

AGENT_NAME = "recon"
STAGE = "reconnaissance"
TACTIC_ID, TACTIC_NAME = "TA0043", "Reconnaissance"
TECHNIQUES = {
    "horizontal": ("T1595.001", "Active Scanning: Scanning IP Blocks"),
    "vertical": ("T1595", "Active Scanning"),
}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def build_alert(f: Finding) -> dict:
    tech_id, tech_name = TECHNIQUES[f.scan_type]
    description = (
        f"{f.src_ip} probed {f.distinct_targets} distinct targets "
        f"({f.distinct_hosts} host(s), {f.distinct_ports} port(s)) within {int(f.window_seconds)}s; "
        f"{int(f.failed_ratio * 100)}% of connections were incomplete, consistent with a "
        f"{f.scan_type} port scan."
    )

    alert = Alert(
        agent=AGENT_NAME,
        stage=STAGE,
        severity=f.severity,
        confidence=f.confidence,
        mitre_tactic_id=TACTIC_ID,
        mitre_tactic=TACTIC_NAME,
        mitre_technique_id=tech_id,
        mitre_technique=tech_name,
        source_ip=f.src_ip,
        description=description,
        evidence={
            "scan_type": f.scan_type,
            "first_seen": _iso(f.first_seen),
            "last_seen": _iso(f.last_seen),
            "window_seconds": f.window_seconds,
            "distinct_targets": f.distinct_targets,
            "distinct_hosts": f.distinct_hosts,
            "distinct_ports": f.distinct_ports,
            "incomplete_connection_ratio": f.failed_ratio,
            "sample_targets": f.sample_targets,
        },
        recommended_actions=[
            f"Confirm whether {f.src_ip} is an authorised scanner; if so, add it to the allowlist.",
            f"If unauthorised, block {f.src_ip} at the firewall and review exposed services on the scanned host(s).",
            f"Share {f.src_ip} with the Delivery and Exploitation agents as a known-scanner indicator.",
        ],
    )

    # alert_id isn't part of the shared schema, but it's useful locally (log correlation,
    # de-duplication) so it's added on top of the schema's own fields rather than inside it.
    return {"alert_id": str(uuid.uuid4()), **alert.to_dict()}


def write_alert(alert: dict, path: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")
