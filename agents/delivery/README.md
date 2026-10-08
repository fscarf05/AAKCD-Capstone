# Delivery Agent

Checks attachment names, disguised extensions, macro-enabled documents, phishing
language and URLs. Files are never executed and URLs are never visited.

## Optional local AI (macOS)

Rules work without Ollama or additional Python packages. To enable Llama 3.2:

1. Install [Ollama for macOS](https://ollama.com/download/mac).
2. Quit the Ollama app if it is running. In Terminal, start a local-only server:

   ```sh
   OLLAMA_NO_CLOUD=1 OLLAMA_HOST=127.0.0.1:11434 ollama serve
   ```

3. In another Terminal, download and warm up the model (the download needs internet):

   ```sh
   ollama pull llama3.2:3b
   ollama run llama3.2:3b "Reply with ready"
   ```

4. From the repository root, run:

   ```sh
   DELIVERY_AI_ENABLED=1 python3 main.py
   ```

Results remain in `outputs/delivery_file_scan.json`. Run `python3 main.py` without
the environment variable for rules only. Python callers can explicitly choose
`DeliveryAgent(ai_enabled=True)` or `DeliveryAgent(ai_enabled=False)`.

The client uses only `127.0.0.1:11434` and `llama3.2:3b`; it ignores proxy and
remote-host environment settings and does not follow redirects. Subject, body,
URL and attachment name are passed to the local model, with field length limits;
other event metadata is omitted. Binary attachment contents are not analysed.
No external AI service, API key or automatic model download is used. Keep the
Ollama server in local-only mode as shown above. See the official
[local-only configuration](https://docs.ollama.com/faq) and
[macOS requirements](https://docs.ollama.com/macos).

## Behaviour and limitations

Existing rule alerts are preserved exactly. A suspicious AI result adds a separate,
clearly labelled alert using the existing `Alert` fields and JSON writer. AI can
flag wording that does not match a keyword. A benign AI verdict never removes a
rule alert. AI findings use medium severity and a fixed 0.5 confidence placeholder,
not a calibrated probability; review the explanation before acting. The model can
make mistakes or be misled by hostile text. It cannot confirm malware from a name.

AI is disabled by default. A connection error, 30-second socket timeout, missing
model, HTTP error, oversized response or invalid JSON disables AI for that agent
instance and logs a generic warning. Rules continue. Restart the program (or create
a new agent) after fixing Ollama. Warm-up avoids cold-start timeouts; large scans
are slower with AI enabled. The timeout applies to socket operations, not a hard
whole-scan deadline. Long input is truncated only for AI; rules still inspect the
original event.

`shared/alert_schema.json` is currently an example with different fields from the
runtime dataclass. This integration preserves the runtime format and leaves both
shared files unchanged. `main.py` and other agents are unchanged.

## Tests

From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install pytest
python3 -m pytest -q
```

AI tests mock Ollama and need no model or network. To run just those tests without
installing pytest: `python3 -m unittest discover -s tests -p 'test_ollama_analysis.py'`.
For a real-model smoke test, run the sample scan with AI enabled and inspect the
labelled AI findings. Model wording and the number of AI findings may vary.

## Evaluate detection quality

Run `python3 -m evaluation.run_delivery` for a rules baseline, or
`python3 -m evaluation.run_delivery --with-ai` for a local AI comparison.
See [the evaluation guide](../../evaluation/README.md) for the 40 labelled
synthetic cases, metrics, limitations and saved reports.
