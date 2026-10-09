import json
from pathlib import Path
from datetime import datetime


def save_agent_output(alerts, filename="agent_outputs.json"):
    """
    Save alerts from the AAKCD agents into a JSON file.
    """

    output_directory = Path("outputs")
    output_directory.mkdir(exist_ok=True)

    output_path = output_directory / filename

    data = []

    for alert in alerts:
        if alert is not None:
            alert_data = alert.to_dict()

            if "timestamp" not in alert_data:
                alert_data["timestamp"] = datetime.now().isoformat()

            data.append(alert_data)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return output_path