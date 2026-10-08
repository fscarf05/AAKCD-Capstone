# Delivery handover to the Wazuh integration owner

## Delivered interface

| Item | Value |
|---|---|
| Logical agent / stage | `delivery` / `delivery` |
| Runtime | Python, currently tested on macOS; local Ollama optional |
| Log format | UTF-8 JSONL, one alert per line, append-only |
| Default log | `<repository>/outputs/delivery/alerts.jsonl` |
| Current VS Code checkout path | `/Users/francescoscarfone/Documents/AAKCD-Capstone/outputs/delivery/alerts.jsonl` |
| Proposed rule allocation | 100210–100214; not yet reserved with the team |
| Correlation source | Valid event `source_ip`; absent when unknown |
| Demo metadata | `evidence.scenario_id`, `evidence.simulation=true` |

Always use the absolute path printed by the program on the actual deployment host.
The example Mac path is not a Linux manager path. Final VM, manager address,
enrolment details and rule allocation still need agreement with the integration
owner. This repository does not provision the manager or enrol machines.

Files supplied:

- `local_rules.xml`: group block for the manager's custom rules.
- `ossec_localfile_snippet.xml`: collection block with a path placeholder.
- `sample_alerts.jsonl`: four safe fixture lines, ordered LOW, MEDIUM, HIGH, CRITICAL.
  LOW is explicitly a transport fixture; the current detector does not emit LOW.
  Fixed fixture timestamps are for logtest, not the live dashboard demo.

## Install and test on the team environment

1. Confirm 100210–100214 are unused across all teammates' rules. If they conflict,
   renumber both rule IDs and `if_sid` references before installation.
2. On the manager, merge the group block into `/var/ossec/etc/rules/local_rules.xml`,
   preserving existing rules. Do not replace the team's entire file. Back it up
   before editing. The parent matches exact `agent` and `stage`; children match
   exact severity and use levels 3, 7, 10, 12 respectively. LOW/MEDIUM are kept below
   HIGH/CRITICAL rather than making every alert equally severe.
3. On the manager, run `/var/ossec/bin/wazuh-logtest` and paste each sample line.
   Confirm JSON decoding and the expected final rule:

   | Severity | Rule | Level |
   |---|---:|---:|
   | LOW | 100211 | 3 |
   | MEDIUM | 100212 | 7 |
   | HIGH | 100213 | 10 |
   | CRITICAL | 100214 | 12 |

   As negative tests, change `agent` to `recon`, `stage` to `exploitation`, or severity
   to lowercase. These records must not match the Delivery severity rules. Other
   installed rules can still match them. Confirm the decoded evidence and source IP.
4. Decide collection mode. For live forwarding, install/enrol a Wazuh agent on the
   log-producing machine with the team's manager details. Add the supplied
   `localfile` block inside its `ossec_config`, replace the location placeholder,
   and ensure the collector can read the file. For manual handover, copy the log
   to a manager-local path and configure collection there. Manual file transfer is
   a separate demonstration mode and must not be described as live forwarding.
5. Apply the configuration using the team's service-management procedure. Restart
   the manager after rule changes and the collector after collection changes.
   Check their logs for invalid configuration or duplicate rule IDs.
6. Start collection, then generate a fresh demo event from the repository root:

   ```sh
   python3 -m agents.delivery.demo --source-ip 192.0.2.10 --scenario-id ransomware-demo-01
   ```

   Replace the IP with the team-agreed simulation IP. Fresh timestamps and a newly
   appended line avoid relying on whether the collector ingests pre-existing lines.
7. Verify the event in the Wazuh dashboard and save evidence of the raw record,
   decoded fields, final rule ID and collection host. A local JSONL file alone is
   not proof of manager ingestion.

## Dashboard and correlation contract

Inspect a received event before building views. With normal Wazuh JSON decoding,
application fields appear under `data`, so use `data.agent`, `data.stage`,
`data.source_ip`, `data.severity`, `data.confidence` and `data.evidence.scenario_id`.
Do not confuse the application's `data.agent` with Wazuh's own `agent.id/name`.
Confirm the actual indexed mapping and keyword aggregations in the deployed version.

The overview should show time, source IP and stage, with a separate Delivery view
showing description, evidence, recommendations, AI status and rule ID. Exclude
unknown IPs from attacker groupings. Filter by scenario ID for the controlled demo.

`source_ip` is a JSON dynamic field; it is not automatically Wazuh's static `srcip`.
For dynamic-field correlation, the rule author should use the appropriate
`same_field` matching, not assume `same_source_ip` applies. The team must test
cross-host scope, ordering and the time window with its actual stage rules.
Matching an IP alone is not proof of one attacker (NAT/shared infrastructure may
combine unrelated events). Do not count two Delivery alerts as two different stages.

No cross-stage correlation rule is activated here: the other stage IDs, host scope
and event order are not yet agreed. The integration owner should demonstrate a
positive same-IP cross-stage case and negative different-IP, expired-window and
same-stage-only cases before claiming chain correlation.

## Acceptance record

Repository checks: shared contract, confidence/severity casing, structured evidence,
recommendations, JSONL append/escaping, no fabricated file IP, simulation metadata,
AI enrichment/fallback and XML structure are covered by automated tests.

Deployment checks still pending:

- Rule range agreed and collision-free.
- `wazuh-logtest` passes all four fixtures and negative cases.
- A newly appended demo line reaches the manager and dashboard.
- The Delivery event joins the team's other stages using the agreed correlation key.
- Dashboard captures and end-to-end timing are recorded for the report.

Wazuh is not installed in the development environment used for these repository
checks. XML parsing and local routing tests are not a substitute for wazuh-logtest.

## References

- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [JSON decoding](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [Log collection configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Rule syntax and dynamic-field correlation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
