from .alert import build_alert, send_alert
from .baseline import load_baseline
from .collectors.windows import collect_all
from .diff import find_new_entries
from .rules import classify

def run_once(host: str) -> list[dict]:
    print(f"[+] Running installation agent against {host}")
    baseline = load_baseline(host)
    current = {"host": host, "platform": "windows", "techniques": collect_all()}
    changes = find_new_entries(baseline, current)
    print(f"[+] Found {len(changes)} new persistence entries")
    alerts = []
    for change in changes:
        technique_id, entry = change["technique_id"], change["entry"]
        severity, confidence = classify(entry, technique_id)
        alert = build_alert(host, technique_id, entry, severity, confidence)
        alerts.append(alert)
        send_alert(alert)
    return alerts
