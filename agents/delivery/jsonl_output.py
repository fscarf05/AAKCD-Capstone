"""Append Delivery alerts as individual JSON records for log collection."""
import json
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parents[2] / 'outputs' / 'delivery' / 'alerts.jsonl'


def append_alerts(alerts, output_path=DEFAULT_LOG):
    path = Path(output_path).expanduser().resolve()
    # Serialize before opening so an invalid record cannot leave a partial batch.
    lines = [json.dumps(alert.to_dict(), ensure_ascii=True, allow_nan=False)
             for alert in alerts]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as stream:
        for line in lines:
            stream.write(line + '\n')
    return path
