# Delivery Agent

Workspace for the Delivery-stage AI agent.

Initial scope:
- Process safe test email data
- Extract URLs and attachment metadata
- Analyse suspicious delivery/phishing indicators
- Map detections to MITRE ATT&CK (for example, T1566 where appropriate)
- Produce structured alerts using `shared/alert_schema.json`
- Forward alerts to the shared integration layer when ready

No live malware is required for development or testing.
