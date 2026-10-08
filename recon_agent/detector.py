"""Deterministic scan detection: sliding window of distinct targets per source IP."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Optional

from zeek_parser import ConnectionEvent

# Zeek conn_states meaning "never became a normal conversation" (typical of scanning):
# S0 no reply, REJ refused, RSTO/RSTOS0 originator reset (nmap -sS / -sT), SH/SHR half-open, OTH no handshake.
SCAN_STATES = frozenset({"S0", "REJ", "RSTO", "RSTOS0", "SH", "SHR", "OTH"})
SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2}
BURST_GAP_SECONDS = 5.0  # a pause this long from one source means a new scan has started


@dataclass
class DetectorConfig:
    window_seconds: float = 60.0
    medium_threshold: int = 20            # distinct (host, proto, port) targets in window
    high_threshold: int = 100
    horizontal_host_threshold: int = 10   # >= this many distinct hosts => horizontal sweep
    cooldown_seconds: float = 300.0       # suppress repeat alerts unless severity escalates
    allowlist: tuple[str, ...] = ()       # CIDRs of authorised scanners, e.g. ("10.0.0.5/32",)


@dataclass
class Finding:
    src_ip: str
    first_seen: float
    last_seen: float
    severity: str
    confidence: str
    scan_type: str               # "vertical" (one host, many ports) or "horizontal" (many hosts)
    distinct_targets: int
    distinct_hosts: int
    distinct_ports: int
    failed_ratio: float
    sample_targets: list[str]
    window_seconds: float


@dataclass
class Suppression:
    """A scan that met the alert threshold but was not alerted because of the cooldown."""
    src_ip: str
    severity: str
    distinct_targets: int
    seconds_since_alert: float
    cooldown_seconds: float


class ScanDetector:
    def __init__(self, config: Optional[DetectorConfig] = None,
                 on_suppressed: Optional[Callable[[Suppression], None]] = None) -> None:
        self.config = config or DetectorConfig()
        self._on_suppressed = on_suppressed
        self._noted_burst: dict[str, bool] = {}  # already reported/alerted during the current scan?
        self._allow = [ipaddress.ip_network(n, strict=False) for n in self.config.allowlist]
        self._events: dict[str, list[ConnectionEvent]] = defaultdict(list)
        self._latest_ts: dict[str, float] = {}
        self._last_alert: dict[str, tuple[float, str]] = {}

    def _is_allowlisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._allow)

    def process(self, ev: ConnectionEvent) -> Optional[Finding]:
        cfg = self.config
        if self._is_allowlisted(ev.src_ip):
            return None

        src = ev.src_ip
        previous = self._latest_ts.get(src)
        if previous is None or ev.ts - previous >= BURST_GAP_SECONDS:
            self._noted_burst[src] = False  # new scan from this source
        # Zeek logs connections when they end, so lines arrive slightly out of order:
        # anchor the window on the newest timestamp seen for this source.
        latest = max(self._latest_ts.get(src, ev.ts), ev.ts)
        self._latest_ts[src] = latest
        cutoff = latest - cfg.window_seconds
        window = [e for e in self._events[src] if e.ts >= cutoff]
        if ev.ts >= cutoff:
            window.append(ev)
        self._events[src] = window

        targets = {(e.dst_ip, e.proto, e.dst_port) for e in window}
        if len(targets) < cfg.medium_threshold:
            return None
        severity = "HIGH" if len(targets) >= cfg.high_threshold else "MEDIUM"

        prev = self._last_alert.get(src)
        if prev:
            prev_ts, prev_sev = prev
            since = latest - prev_ts
            if since < cfg.cooldown_seconds and SEVERITY_RANK[severity] <= SEVERITY_RANK[prev_sev]:
                self._note_suppressed(src, severity, len(targets), since, latest)
                return None
        self._last_alert[src] = (latest, severity)

        self._noted_burst[src] = True  # the scan that just alerted needs no suppression note
        hosts = {t[0] for t in targets}
        ports = {(t[1], t[2]) for t in targets}
        failed_ratio = sum(e.conn_state in SCAN_STATES for e in window) / len(window)
        if failed_ratio >= 0.8:
            confidence = "high"
        elif failed_ratio >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"

        return Finding(
            src_ip=src,
            first_seen=min(e.ts for e in window),
            last_seen=latest,
            severity=severity,
            confidence=confidence,
            scan_type="horizontal" if len(hosts) >= cfg.horizontal_host_threshold else "vertical",
            distinct_targets=len(targets),
            distinct_hosts=len(hosts),
            distinct_ports=len(ports),
            failed_ratio=round(failed_ratio, 2),
            sample_targets=[f"{h}:{p}/{pr}" for h, pr, p in sorted(targets)[:10]],
            window_seconds=cfg.window_seconds,
        )


    def _note_suppressed(self, src: str, severity: str, count: int, since: float, now: float) -> None:
        """Report a suppressed scan once per scan (not once per packet)."""
        if self._on_suppressed is None or self._noted_burst.get(src):
            return
        self._noted_burst[src] = True
        self._on_suppressed(Suppression(src, severity, count, round(since, 1), self.config.cooldown_seconds))
