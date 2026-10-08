# Delivery Agent

Delivery-stage detection for AAKCD. The agent checks attachment names, disguised
extensions, macro-enabled documents, phishing keywords and URLs. Optional local
Llama 3.2 analysis adds explanations and separate AI findings. It never executes
attachments or visits URLs.

## Run

From the repository root:

```sh
python3 main.py
```

This scans `test_samples`, saves a JSON snapshot to
`outputs/delivery_file_scan.json`, and appends alerts to
`outputs/delivery/alerts.jsonl`. The absolute JSONL path is printed at completion.
The JSONL default is anchored to this repository, not the terminal's directory.
Use `--directory PATH` to scan another folder, or `--log-path PATH` to choose a log.
Repeated runs append repeated observations. Only run one writer per log file;
rotation, retention and deduplication are deployment responsibilities.

## Local AI on macOS

Install [Ollama](https://ollama.com/download/mac). Quit the desktop app before
starting a local-only server in Terminal:

```sh
OLLAMA_NO_CLOUD=1 OLLAMA_HOST=127.0.0.1:11434 ollama serve
```

In a second terminal:

```sh
ollama pull llama3.2:3b
ollama run llama3.2:3b "Reply with ready"
DELIVERY_AI_ENABLED=1 python3 main.py
```

Only the model download needs internet. The client uses fixed loopback
`127.0.0.1:11434`, ignores HTTP proxies and remote-host settings, and does not
follow redirects. No external AI service or API key is used. Input is limited to
attachment name, subject, body and URL; individual lengths are bounded.
See [Ollama local-only configuration](https://docs.ollama.com/faq).

AI is off by default. Python callers can use `DeliveryAgent(ai_enabled=True)`.
Connection failures, a 30-second socket timeout or HTTP errors disable AI for that
instance. A malformed answer falls back for its event; three consecutive malformed
answers disable AI. Restart or create a new agent after resolving a service failure.
Diagnostics record safe error codes. AI cannot remove or downgrade a rule alert.

## Team alert contract

`shared/alert_schema.py` and `.json` are the team-supplied files, copied unchanged.
The JSON file is field documentation, not an executable JSON Schema validator.
Every alert uses `agent=delivery`, `stage=delivery`, uppercase severity, categorical
confidence, separate MITRE ID/name, structured evidence and recommended actions.
Timestamps are UTC and supplied by the shared dataclass.

| Detection | Severity | Confidence | Technique |
|---|---|---|---|
| Disguised attachment | CRITICAL | high | T1566.001 |
| Suspicious attachment extension | HIGH | high | T1566.001 |
| Macro-enabled document | HIGH | high | T1566.001 |
| Phishing keywords | MEDIUM | medium | T1566 |
| Suspicious URL keyword | HIGH | high | T1566.002 |
| AI-only finding | MEDIUM | low | Selected from those three techniques |

Confidence expresses heuristic strength, not a calibrated probability. Former
rule scores 0.80–0.95 map to high, 0.75 to medium; the AI's former 0.5 placeholder
maps to low. These mappings do not demonstrate detection accuracy.

Rule evidence records detector name and matched filenames/extensions, keywords or
URL. File scans add `source_file`. Unknown or invalid source IPs are omitted;
no address is inferred from a file. Valid event IPs are retained for correlation.

When AI runs, existing rule alerts receive `ai_status=ok` and `ai_summary`, including
benign AI opinions that disagree with rules. Failures use `ai_status=unavailable`
and an error code in evidence. With AI disabled, AI fields are omitted. A suspicious
AI verdict may also append a separate low-confidence finding. Recommendations are
rule-authored; `ai_recommended_actions` is omitted because the model does not
currently generate recommendations. No response action is executed automatically.

## Demo and integration

```sh
python3 -m agents.delivery.demo --source-ip 192.0.2.10 --scenario-id ransomware-demo-01
```

This is a safe, labelled simulation of an unsolicited disguised attachment. It
produces one critical rule alert without creating or running malware. Replace the
example documentation IP with the source IP agreed for the team's scenario. Add
`--with-ai` for optional analysis, which may add an alert. This command implements
only Delivery; other stages and cross-stage correlation belong to the team demo.

See [Wazuh handover](../../wazuh/delivery/README.md) for sample lines, proposed rule
IDs, collection configuration, dashboard fields and acceptance checks.

## Evaluation and tests

```sh
python3 -m evaluation.run_delivery
python3 -m evaluation.run_delivery --with-ai --output-dir outputs/evaluation_schema
python3 -m unittest discover -s tests -v
```

The unittest command covers class-based tests. Install pytest in your project
virtual environment and run `python3 -m pytest -q` to include the original
function-based tests as well. See [evaluation guide](../../evaluation/README.md).

The 40-case synthetic rules baseline remains TP=12, FP=8, TN=12, FN=8. The earlier
complete local-AI evaluation did not improve those predictions. This schema
migration is an integration change, not a detection-quality improvement.

Limitations: filename checks do not inspect binary payloads; text scanning is not
a full MIME/email parser; a directory scan is a one-shot batch, not a mail gateway
or filesystem watcher. AI can miss threats or be misled. Logs can contain filenames,
URLs and model explanations; apply appropriate access control in deployment.
