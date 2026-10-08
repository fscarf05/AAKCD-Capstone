import argparse

from agents.delivery.delivery_agent import DeliveryAgent
from shared.json_output import save_agent_output
from agents.delivery.jsonl_output import append_alerts, DEFAULT_LOG


def run_delivery_agent(directory="test_samples", log_path=DEFAULT_LOG):

    print()
    print("=" * 55)
    print("AAKCD DELIVERY AGENT")
    print("REAL FILE SCANNING TEST")
    print("=" * 55)

    # Create Delivery Agent
    delivery_agent = DeliveryAgent()

    # Folder containing the test files
    test_folder = directory

    # Scan every file in the folder
    alerts = delivery_agent.scan_directory(
        test_folder
    )

    jsonl_path = append_alerts(alerts, log_path)

    # Save detected alerts to JSON
    output_file = save_agent_output(
        alerts,
        "delivery_file_scan.json"
    )

    print()
    print("=" * 55)
    print("DELIVERY AGENT COMPLETE")
    print("=" * 55)

    print(
        f"Files scanned from: {test_folder}"
    )

    print(
        f"Total alerts detected: {len(alerts)}"
    )

    print(
        f"JSON results saved to: {output_file}"
    )

    print(f"Wazuh JSONL log: {jsonl_path}")
    print("=" * 55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan Delivery samples and write shared-schema alerts")
    parser.add_argument("--directory", default="test_samples")
    parser.add_argument("--log-path", default=DEFAULT_LOG)
    args = parser.parse_args()
    run_delivery_agent(args.directory, args.log_path)
