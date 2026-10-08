# Delivery integration: design and validation

## Purpose

The Delivery Agent identifies suspicious delivery-stage events and supplies
consistent alerts to the AAKCD collection layer. This update adopts the team's
shared alert contract and prepares Delivery for a coordinated ransomware scenario.
It does not implement the other agents, run ransomware or deploy the shared manager.

## Processing path

```text
Event dictionary or file scan
        |
        v
Existing Delivery rules ----> rule alerts
        |                         |
        +--> optional local AI ---+--> shared Alert objects
                                      |
                         +------------+------------+
                         v                         v
                  JSON snapshot             append JSONL
                                                  |
                                    Wazuh log collector [deployment]
                                                  |
                                    manager rules / dashboard [deployment]
```

The AI step is sequential for each event. This module alone does not demonstrate
parallel execution across kill-chain stages. The collector-to-manager path remains
a team deployment task.

## Decisions

- Adopt the supplied dataclass and documentation without modifying the team contract.
  Other branches must migrate their constructors when integrating that contract.
- Preserve detection decisions and the disguised-extension early return. Avoid
  mixing an interface migration with detector tuning.
- Use structured evidence rather than extracting facts back out of descriptions.
  Preserve source IP only when it is a valid supplied address; record file location
  separately. Delivery does not infer an attacker from a filename.
- Keep AI opinions separate from rule decisions. AI can enrich an alert or add a
  low-confidence finding, but cannot suppress a rule detection. Recommendations
  require analyst review and are not automated containment actions.
- Keep the existing snapshot for inspection and add append-only JSONL for collection.
  Evaluation does not append to the production log; only main.py and the demo write
  there by default. This avoids feeding all evaluation cases into the team dashboard.
- Propose Delivery IDs 100210–100214, subject to team confirmation. Do not install
  correlation rules until the integration owner confirms the other stage IDs and
  tests the combined stream.

## Validation and evidence

Automated tests cover existing detections, local AI parsing and failure recovery,
evaluation calculations, shared-schema fields, evidence, recommendations, UTC
timestamps, IP handling, JSONL framing, simulation metadata and XML structure.
The 40-case rules baseline remains 12 true positives, 8 false positives, 12 true
negatives and 8 false negatives. The sample file scan still generates four alerts.

`wazuh/delivery/sample_alerts.jsonl` contains deterministic handover fixtures.
The demo emits a fresh timestamp with an explicit simulation marker and scenario
ID. The source IP is a correlation fixture, not evidence of a real attacker.

The repository tests do not prove manager ingestion, Wazuh rule execution,
cross-stage ordering or dashboard visibility. Record those results using the
acceptance steps in `wazuh/delivery/README.md` before describing integration as
complete in the final report.

## Limitations

This is a prototype, not a malware classifier or production mail gateway. Attachment
checks inspect names/extensions; text scanning does not fully parse MIME. Heuristic
confidence is categorical, not statistically calibrated. The small synthetic
benchmark is for development, and the completed pre-migration AI evaluation did
not improve classification over rules. Independent evaluation is needed after any
prompt or rule tuning.

JSONL writing assumes one local process per file. There is no rotation, deduplication,
message queue or delivery acknowledgement. A write error stops the caller rather
than reporting a successful log export. Multiple alerts may describe the same event;
the correlation layer must distinguish repeated detections from progression across
stages. Protect logs appropriately, since they can include sensitive URLs or paths.

## Team decisions still required

The integration owner needs to confirm the rule-ID allocation, hosting machine,
manager endpoint, log-forwarding approach and shared simulation IP. The team also
needs to agree its correlation window and verify clock synchronisation. These are
handover dependencies, not settings silently assumed by the Delivery Agent.

## Validation run: 8 October 2026

- Full pytest suite: 38 passed, with 17 passing subtests.
- Team schema files compared byte for byte with the supplied attachments: identical.
- Main sample scan: four detections, each written using the new contract.
- Real local Ollama demo: completed; source IP, AI enrichment and JSONL decoding checked.
- Real local Ollama evaluation: all 40 cases completed, no fallback failures.
  Rules and hybrid both produced TP=12, FP=8, TN=12, FN=8; precision/recall/F1=0.60.
  Hybrid mean event time in this run was approximately 1.54 seconds.
- Wazuh fixture routing and XML structure checked locally. Manager-side logtest,
  forwarding, dashboard visibility and cross-stage correlation remain unverified.

These results demonstrate compatibility and preserved behaviour. They do not
establish improved AI detection or a completed six-stage deployment.
