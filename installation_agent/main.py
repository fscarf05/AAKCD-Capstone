import argparse
import sys

from installation_agent.agent import run_once
from installation_agent.baseline import capture_baseline, baseline_path


def main():
    parser = argparse.ArgumentParser(
        description="Standalone Windows Installation/Persistence Detection Agent"
    )

    parser.add_argument(
        "command",
        choices=["baseline", "scan"],
        help="Create a baseline or run a detection scan.",
    )

    parser.add_argument(
        "--host",
        default="vm-target-01",
        help="Logical hostname used for the baseline filename.",
    )

    args = parser.parse_args()

    if args.command == "baseline":
        print(f"[+] Creating baseline for {args.host}...")
        snapshot = capture_baseline(args.host)

        print(f"[+] Baseline saved to: {baseline_path(args.host)}")

        for technique_id, entries in snapshot["techniques"].items():
            print(f"    {technique_id}: {len(entries)} entries")

        return 0

    if args.command == "scan":
        try:
            alerts = run_once(args.host)
        except FileNotFoundError as error:
            print(f"[!] {error}")
            return 1

        if not alerts:
            print("[+] No new persistence entries detected.")

        return 0


if __name__ == "__main__":
    sys.exit(main())
