SUSPICIOUS_PATHS = (r"\appdata\local\temp", r"\appdata\roaming", r"\windows\temp", r"\users\public", r"\downloads")
TRUSTED_PATHS = (r"c:\windows\system32", r"c:\windows\syswow64", r"c:\program files", r"c:\program files (x86)")

def path_is_suspicious(value: str) -> bool:
    value = str(value or "").lower()
    return any(path in value for path in SUSPICIOUS_PATHS)

def path_is_trusted(value: str) -> bool:
    value = str(value or "").lower()
    return any(path in value for path in TRUSTED_PATHS)

def classify(entry: dict, technique_id: str) -> tuple[str, str]:
    """Return schema-compliant (severity, confidence); these are heuristics."""
    field = "command" if technique_id == "T1053.005" else "path"
    path = str(entry.get(field, "") or "")
    if technique_id == "T1543.003" and path_is_suspicious(path) and str(entry.get("start_mode", "")).lower() == "auto":
        return "HIGH", "medium"
    if path_is_suspicious(path):
        return "HIGH", "medium"
    if path_is_trusted(path):
        return "LOW", "medium"
    return "MEDIUM", "low"
