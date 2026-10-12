import json


def create_entry_key(entry: dict) -> str:
    """Create a stable representation for comparison."""
    return json.dumps(entry, sort_keys=True, default=str)


def find_new_entries(baseline: dict, current: dict) -> list[dict]:
    """Return entries present in current state but absent from baseline."""
    results = []

    baseline_techniques = baseline.get("techniques", baseline)
    current_techniques = current.get("techniques", current)

    for technique_id, current_entries in current_techniques.items():
        baseline_entries = baseline_techniques.get(technique_id, [])

        baseline_keys = {
            create_entry_key(entry)
            for entry in baseline_entries
        }

        for entry in current_entries:
            if create_entry_key(entry) not in baseline_keys:
                results.append({
                    "technique_id": technique_id,
                    "entry": entry,
                })

    return results
