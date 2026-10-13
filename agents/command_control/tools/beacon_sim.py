#!/usr/bin/env python3
"""
beacon_sim.py - generates benign, labelled beaconing traffic for the AAKCD lab.

Run this on the victim VM. It contacts a listener on the attacker VM at a fixed
interval with a small amount of jitter, which is exactly the pattern the C2
detection agent is meant to pick up.

This is a traffic generator, not malware. It only sends HTTP GET requests.
Run it on a host-only network so nothing leaves the lab.

Usage:
    python3 beacon_sim.py --host 192.168.56.20 --port 8000 --interval 60 --jitter 5
"""

import argparse
import random
import time
import urllib.request
import urllib.error


def main():
    p = argparse.ArgumentParser(description="Generate beaconing traffic for detection testing.")
    p.add_argument("--host", required=True, help="Listener IP on the attacker VM")
    p.add_argument("--port", type=int, default=8000, help="Listener port")
    p.add_argument("--interval", type=float, default=60.0, help="Seconds between check-ins")
    p.add_argument("--jitter", type=float, default=0.0,
                   help="Percent jitter around the interval, e.g. 5 for +/-5 percent")
    p.add_argument("--count", type=int, default=50, help="Number of check-ins before stopping")
    p.add_argument("--path", default="/checkin", help="URL path to request")
    args = p.parse_args()

    url = f"http://{args.host}:{args.port}{args.path}"
    print(f"[*] Beaconing to {url}")
    print(f"[*] interval={args.interval}s jitter={args.jitter}% count={args.count}")

    for i in range(1, args.count + 1):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                r.read()
            status = "ok"
        except urllib.error.URLError as e:
            status = f"failed ({e.reason})"
        except Exception as e:
            status = f"failed ({e})"

        print(f"[{i}/{args.count}] {time.strftime('%H:%M:%S')} check-in {status}")

        if i == args.count:
            break

        offset = args.interval * (args.jitter / 100.0)
        sleep_for = args.interval + random.uniform(-offset, offset)
        time.sleep(max(0.1, sleep_for))

    print("[*] Done. Now run Zeek over the capture and feed conn.log to c2_detect.py")


if __name__ == "__main__":
    main()
