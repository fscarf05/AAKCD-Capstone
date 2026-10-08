"""Recon Agent entry point.

  python run_agent.py --log sample_conn.log                  # one-off analysis
  python run_agent.py --log /opt/zeek/logs/current/conn.log --follow   # live on the victim VM
  add --ai to have the CrewAI/Gemini analyst explain each alert (needs GEMINI_API_KEY)
"""
from __future__ import annotations

import argparse
import json
import sys

from alerts import build_alert, write_alert
from detector import DetectorConfig, ScanDetector, Suppression
from enrich import enrich_alert
from zeek_parser import follow_file, read_file


def main() -> None:
    p = argparse.ArgumentParser(description="AAKCD Reconnaissance Agent")
    p.add_argument("--log", required=True, help="Path to Zeek conn.log")
    p.add_argument("--out", default="recon_alerts.jsonl", help="Alert output file (JSON lines)")
    p.add_argument("--follow", action="store_true", help="Keep watching the log for new lines")
    p.add_argument("--from-start", action="store_true",
                   help="With --follow: also analyse lines already in the log (default: only new lines)")
    p.add_argument("--window", type=float, default=60.0)
    p.add_argument("--medium", type=int, default=20)
    p.add_argument("--high", type=int, default=100)
    p.add_argument("--allow", action="append", default=[], help="Allowlisted CIDR (repeatable)")
    p.add_argument("--cooldown", type=float, default=300.0,
                   help="Seconds before the same source can alert again at the same severity "
                        "(default 300; use e.g. 30 for testing and demos)")
    p.add_argument("--ai", action="store_true", help="Add CrewAI/Gemini explanation to each alert")
    args = p.parse_args()

    def show_suppressed(s: Suppression) -> None:
        print(f"[suppressed] {s.src_ip} still scanning ({s.distinct_targets} targets, would be {s.severity}): "
              f"last alert {s.seconds_since_alert:.0f}s ago, cooldown {s.cooldown_seconds:.0f}s",
              file=sys.stderr, flush=True)

    detector = ScanDetector(DetectorConfig(
        window_seconds=args.window,
        medium_threshold=args.medium,
        high_threshold=args.high,
        cooldown_seconds=args.cooldown,
        allowlist=tuple(args.allow),
    ), on_suppressed=show_suppressed)
    if args.follow:
        events = follow_file(args.log, from_start=args.from_start)
        which = "all lines" if args.from_start else "new lines only"
        print(f"Watching {args.log} ({which}). Press Ctrl+C to stop.", file=sys.stderr, flush=True)
    else:
        events = read_file(args.log)

    count = 0
    try:
        for ev in events:
            finding = detector.process(ev)
            if finding:
                alert = build_alert(finding)
                if args.ai:
                    alert = enrich_alert(alert)
                write_alert(alert, args.out)
                print(json.dumps(alert, indent=2))
                count += 1
    except KeyboardInterrupt:
        print("\nStopped by user.")
    print(f"Done: {count} alert(s) written to {args.out}")


if __name__ == "__main__":
    main()
