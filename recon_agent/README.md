# Recon Agent (AAKCD)

Part of the AAKCD Cyber Kill Chain Defence project. This agent watches network
traffic and alerts when it sees someone scanning the network, the
Reconnaissance stage of the Cyber Kill Chain (MITRE ATT&CK TA0043).

## What it does, in plain words

1. Reads traffic logs produced by Zeek (a network monitoring tool).
2. Counts how many different ports/hosts each source IP touches in a
   60-second window.
   - 20+ targets = MEDIUM alert
   - 100+ targets = HIGH alert
3. Works out whether it's a scan of one machine (vertical) or a scan across
   many machines (horizontal), and labels it with the matching MITRE
   ATT&CK technique.
4. Optionally sends the alert to Gemini (through CrewAI) to get a
   plain-English explanation, a likely intent, and recommended actions.
   This step is just explanation, not detection, and never changes the
   severity or the MITRE mapping. If Gemini is slow or down, the alert
   still goes out without it.
5. Writes every alert as one line of JSON to an output file, which Wazuh
   will read.

## Files

| File | What it does |
|---|---|
| `zeek_parser.py` | Reads Zeek's `conn.log` and turns each line into a connection event. Keeps working even when Zeek rotates to a new log file. |
| `detector.py` | The detection rule: counts targets per source IP, decides severity, scan type, and confidence. |
| `alerts.py` | Turns a detection into the shared alert JSON format. |
| `enrich.py` | Sends the alert to Gemini via CrewAI for a plain-English explanation. |
| `run_agent.py` | Main entry point. Ties everything together. |
| `test_recon_agent.py` | 30 automated tests. Run these after any change. |
| `make_sample_log.py` | Generates a fake Zeek log so you can test without a real attack. |
| `wazuh/` | Config files for sending alerts into Wazuh. |

## Setup (one-time)

```
python3 -m venv venv
source venv/bin/activate
pip install "crewai[google-genai]"
export GEMINI_API_KEY="your-own-key-here"
```

Get a free key at https://aistudio.google.com (API key). Never commit a
key to this repo, each person uses their own, set as an environment
variable.

## Running it

Test on fake data first:
```
python make_sample_log.py
python run_agent.py --log sample_conn.log --out alerts.jsonl
```

Run for real, watching Zeek's live log, with AI explanations on, and a
short 30-second cooldown (good for testing/demos; use the default for
normal running):
```
python run_agent.py --log /opt/zeek/logs/current/conn.log \
    --follow --ai --cooldown 30 --out alerts.jsonl
```

Run the tests (do this after pulling any update):
```
python -m unittest
```
Expect `Ran 30 tests ... OK`.

## Alert format (proposed shared schema)

Every alert is one JSON object with these fields. Other agents should use
the same field names so the Wazuh dashboard can show all six agents on
one timeline:

```
agent_name, kill_chain_stage, severity, confidence,
mitre_tactic_id, mitre_tactic, mitre_technique_id, mitre_technique,
src_ip, summary, evidence, recommendations,
ai_status, ai_analyst_summary, ai_likely_intent, ai_recommended_actions
```

## Known limitations (honest, for the report)

- Only detects port/network scanning (T1595, T1595.001). Vulnerability
  scanning (T1595.002) isn't covered yet.
- A very slow scan (one port every few seconds) can go undetected by
  design, documented in a test.
- Thresholds (20 / 100 targets) are starting values, not yet calibrated
  against a measured baseline of normal traffic.
- Runs as root to read Zeek's logs, fine for this lab, not for
  production use.
