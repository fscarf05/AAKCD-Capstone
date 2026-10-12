import json
from pathlib import Path

from .collectors.windows import collect_all


BASELINE_DIR = Path(__file__).resolve().parent.parent / "baselines"


def baseline_path(host: str) -> Path:
    safe_host = "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in host
    )
    return BASELINE_DIR / f"{safe_host}.json"


def capture_baseline(host: str) -> dict:
    """Capture and save a known-good persistence baseline."""
    snapshot = {
        "host": host,
        "platform": "windows",
        "techniques": collect_all(),
    }

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)

    with baseline_path(host).open("w", encoding="utf-8") as file:
        json.dump(snapshot, file, indent=4)

    return snapshot


def load_baseline(host: str) -> dict:
    """Load a previously saved baseline."""
    path = baseline_path(host)

    if not path.exists():
        raise FileNotFoundError(
            f"No baseline exists for host '{host}'. "
            "Create one before running detection."
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)
