"""AI enrichment: a CrewAI agent (Gemini) explains a recon alert for a SOC analyst.

Detection is NOT done here. The rule-based detector decides whether an alert exists, its
severity and its MITRE mapping; the LLM only adds an explanation (ai_* fields).
If the LLM is unavailable for any reason (no key, rate limit, network, bad output),
the alert is returned unchanged with ai_status = "unavailable", so detection never depends on the API.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

DEFAULT_MODEL = "gemini/gemini-3.8-flash"
DEFAULT_TIME_BUDGET = 20.0  # seconds per alert, across all models tried
REQUIRED_KEYS = ("analyst_summary", "likely_intent", "recommended_actions")
# Not sent to the LLM: alert_id/timestamp describe the alert itself (the model mistook the alert's
# creation time for the scan time), and recommendations made it copy the rule-based advice verbatim.
EXCLUDED_FROM_PROMPT = ("alert_id", "timestamp", "recommendations")


def _alert_as_text(value, prefix: str = "") -> list[str]:
    """Flatten the alert into 'key: value' lines (no braces, so CrewAI can't misread it as a template)."""
    lines = []
    if isinstance(value, dict):
        for k, v in value.items():
            lines += _alert_as_text(v, f"{prefix}{k}.")
    elif isinstance(value, list):
        lines.append(f"{prefix[:-1]}: " + ", ".join(str(v) for v in value))
    else:
        lines.append(f"{prefix[:-1]}: {value}")
    return lines


def build_prompt(alert: dict) -> str:
    facts = "\n".join(_alert_as_text({k: v for k, v in alert.items() if k not in EXCLUDED_FROM_PROMPT}))
    return (
        "You are reviewing an alert produced by a rule-based network reconnaissance detector.\n\n"
        f"ALERT FACTS:\n{facts}\n\n"
        "Write for a junior SOC analyst. Use ONLY the facts above; do not invent IP addresses, "
        "ports, hostnames or tool names. Do not change the severity or the MITRE ATT&CK mapping. "
        "The activity happened between evidence.first_seen and evidence.last_seen (UTC); "
        "use those times if you mention when it happened.\n\n"
        "Respond with ONLY a JSON object (no markdown) with exactly these keys:\n"
        "analyst_summary: 2-3 sentences explaining what happened and why it matters\n"
        "likely_intent: one sentence on what the attacker is probably trying to learn\n"
        "recommended_actions: a list of 3 short investigation or response steps in priority order, "
        "each tied to specific evidence above (the source IP, the scan type, or the targeted "
        "hosts and ports), not generic advice"
    )


def parse_llm_json(text: str) -> dict:
    """Extract and validate the JSON object from the LLM's reply."""
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in LLM output")
    data = json.loads(cleaned[start:end + 1])
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise ValueError(f"LLM output missing keys: {missing}")
    if not isinstance(data["recommended_actions"], list):
        raise ValueError("recommended_actions is not a list")
    return {k: data[k] for k in REQUIRED_KEYS}


def _run_crew(alert: dict, model: str) -> str:
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")  # no CrewAI telemetry
    from crewai import LLM, Agent, Crew, Task          # imported here so tests run without CrewAI
    logging.getLogger().setLevel(logging.CRITICAL)     # failures are reported in ai_error instead

    llm = LLM(model=model, temperature=0.2, timeout=15)
    analyst = Agent(
        role="SOC Reconnaissance Analyst",
        goal="Explain reconnaissance alerts accurately so a junior analyst knows what happened and what to do next",
        backstory="An experienced blue-team analyst who triages network scanning alerts mapped to MITRE ATT&CK.",
        llm=llm,
        allow_delegation=False,
        max_retry_limit=0,   # no agent-level retries: a busy API must not delay detection
        verbose=False,
    )
    task = Task(
        description=build_prompt(alert),
        expected_output="A single JSON object with keys analyst_summary, likely_intent, recommended_actions",
        agent=analyst,
    )
    return str(Crew(agents=[analyst], tasks=[task], verbose=False).kickoff().raw)


def _call_with_timeout(fn, timeout: float, *args):
    """Run fn in a daemon thread; give up after `timeout` seconds (the thread is abandoned)."""
    box: dict = {}

    def target():
        try:
            box["result"] = fn(*args)
        except BaseException as exc:
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError(f"no reply within {timeout:.0f}s")
    if "error" in box:
        raise box["error"]
    return box["result"]


def configured_models() -> list[str]:
    """AAKCD_LLM_MODEL may list backups, comma-separated: 'gemini/a,gemini/b'."""
    raw = os.environ.get("AAKCD_LLM_MODEL", DEFAULT_MODEL)
    return [m.strip() for m in raw.split(",") if m.strip()]


def enrich_alert(alert: dict, model: str | None = None, time_budget: float | None = None) -> dict:
    models = [model] if model else configured_models()
    if time_budget is None:
        time_budget = float(os.environ.get("AAKCD_LLM_TIMEOUT", DEFAULT_TIME_BUDGET))
    enriched = dict(alert)
    if not os.environ.get("GEMINI_API_KEY"):
        enriched.update(ai_status="unavailable", ai_error="GEMINI_API_KEY not set")
        return enriched

    deadline = time.monotonic() + time_budget
    errors = []
    for m in models:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            errors.append(f"{m}: skipped, {time_budget:.0f}s budget used up")
            break
        try:
            result = parse_llm_json(_call_with_timeout(_run_crew, remaining, alert, m))
        except Exception as exc:  # any LLM failure must never break detection
            errors.append(f"{m}: {type(exc).__name__}: {str(exc)[:150]}")
            continue
        enriched.update(
            ai_status="ok",
            ai_model=m,
            ai_analyst_summary=result["analyst_summary"],
            ai_likely_intent=result["likely_intent"],
            ai_recommended_actions=result["recommended_actions"],
        )
        return enriched

    enriched.update(ai_status="unavailable", ai_error=" | ".join(errors)[:400])
    return enriched
