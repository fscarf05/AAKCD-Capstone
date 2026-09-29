from agents.delivery.delivery_agent import DeliveryAgent
from shared.json_output import save_agent_output


def run_delivery_agent():

    print()
    print("=" * 55)
    print("AAKCD DELIVERY AGENT")
    print("REAL FILE SCANNING TEST")
    print("=" * 55)

    # Create Delivery Agent
    delivery_agent = DeliveryAgent()

    # Folder containing the test files
    test_folder = "test_samples"

    # Scan every file in the folder
    alerts = delivery_agent.scan_directory(
        test_folder
    )

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

    print("=" * 55)


if __name__ == "__main__":
    run_delivery_agent()