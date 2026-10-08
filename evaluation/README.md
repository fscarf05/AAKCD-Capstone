# Delivery Agent evaluation

Run from the repository root, with no extra Python dependencies:

```sh
python3 -m evaluation.run_delivery
```

For rules versus rules plus local Llama 3.2, keep your local-only Ollama server
running and warm the model first (see the Delivery Agent setup instructions):

```sh
ollama run llama3.2:3b "Reply with ready"
python3 -m evaluation.run_delivery --with-ai
```

The 40 sequential AI calls can take several minutes. Results are saved to
`outputs/delivery_evaluation/results.json` and `summary.md`. Each run overwrites
those files; use `--output-dir outputs/evaluation_run_2` to retain another run.
Outputs are ignored by Git. No sample links are visited or attachments executed.

## What is measured

Each event is a positive prediction if the agent returns at least one alert.
Multiple alerts for one event count once. TP/FP/TN/FN compare that prediction with
the human-reviewable label, not the model's own verdict. Precision is TP/(TP+FP),
recall is TP/(TP+FN), F1 is 2TP/(2TP+FP+FN), false-positive rate is FP/(FP+TN), and
accuracy is (TP+TN)/all cases. Undefined ratios are null in JSON and N/A in Markdown.

JSON includes per-case alerts, false positives/negatives, category summaries,
mean/total/p95 event latency (nearest-rank p95), dataset hash, model name, Python
version and platform. Timings include local inference and any cold-start cost;
they do not measure cross-agent response or end-to-end containment time. Record
`ollama --version`, `ollama list`, your Git commit and Mac hardware with your report
for reproducibility. Repeat warmed runs to assess variability.

Rules mode explicitly disables AI regardless of environment variables. The AI
comparison uses the real DeliveryAgent fallback: a service failure disables AI,
while an isolated malformed answer allows the next case to try AI. Three consecutive
invalid answers disable AI. Each failed case remains marked failed, even if later
cases succeed. Such runs still save diagnostic results but exit with code 2 and
mark `valid_full_ai_comparison` false. Do not present them as completed AI results.
A completed benign AI verdict is counted as completed even when no alert is added.
The JSON also records `ai_error` codes and `ai_finding` (including benign verdicts),
so missed threats can be distinguished from failed requests. The Markdown summary
identifies failed case IDs and error codes. Treat saved AI explanations as potentially
sensitive if you replace these synthetic examples with private data.

## Dataset scope

`delivery_cases.json` contains 40 authored, synthetic development examples: 20
suspicious and 20 benign. Each has an ID, category, label, rationale and event.
Only event fields go to the agent; labels and rationales are never sent to Ollama.
Cases cover attachments, phishing language, URLs, keyword-free social engineering,
benign keyword matches and one prompt-injection attempt. Domains use `.example`
and an IP uses the documentation range. There is no real malware or personal data.

Labels mean suspicious enough for analyst review, not confirmed malware. A normal
extension or plausible URL does not prove safety. Review labels with your mentor
and team. This small, balanced dataset is a development check, not a validated
benchmark or estimate of real-world accuracy. It does not test binary payloads,
real email parsing, all attack types or integration with other agents.

Use these results to find weaknesses. If you tune prompts or rules using these
cases, evaluate the final version on a separate, independently labelled holdout
set. Do not claim improvement just because the hybrid produces more alerts:
it may add false positives. Because rules are preserved, AI cannot remove an
existing rule false positive. Inspect `additional_true_positives` and
`additional_false_positives` alongside latency and explanations.

## Tests

```sh
python3 -m unittest discover -s tests -p 'test_delivery_evaluation.py' -v
```

These tests validate metrics, dataset validation, report generation and AI
success/failure accounting without needing a model. With pytest installed,
`python3 -m pytest -q` runs the entire project's tests.
