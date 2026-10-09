"""Parse Zeek conn.log (TSV or JSON) into ConnectionEvent objects."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional


@dataclass(frozen=True)
class ConnectionEvent:
    ts: float          # epoch seconds (connection start)
    src_ip: str        # id.orig_h
    dst_ip: str        # id.resp_h
    dst_port: int      # id.resp_p (ICMP: type/code)
    proto: str         # tcp / udp / icmp
    conn_state: str    # Zeek conn_state, e.g. S0, REJ, SF


def _parse_ts(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


class ZeekConnParser:
    """Stateful line parser. Handles Zeek's TSV header (#separator, #fields) and JSON logs."""

    def __init__(self) -> None:
        self.sep = "\t"
        self.fields: Optional[list[str]] = None

    def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        line = line.rstrip("\r\n")
        if not line:
            return None
        if line.startswith("{"):
            try:
                return self._from_record(json.loads(line))
            except json.JSONDecodeError:
                return None
        if line.startswith("#"):
            if line.startswith("#separator"):
                token = line.split(" ", 1)[1]
                self.sep = token.encode("ascii").decode("unicode_escape")
            elif line.startswith("#fields"):
                self.fields = line.split(self.sep)[1:]
            return None
        if self.fields is None:
            return None
        return self._from_record(dict(zip(self.fields, line.split(self.sep))))

    @staticmethod
    def _from_record(rec: dict) -> Optional[ConnectionEvent]:
        try:
            return ConnectionEvent(
                ts=_parse_ts(rec["ts"]),
                src_ip=str(rec["id.orig_h"]),
                dst_ip=str(rec["id.resp_h"]),
                dst_port=int(rec["id.resp_p"]),
                proto=str(rec.get("proto", "-")),
                conn_state=str(rec.get("conn_state", "-")),
            )
        except (KeyError, TypeError, ValueError):
            return None  # unset ("-") or malformed field


def read_file(path: str) -> Iterator[ConnectionEvent]:
    parser = ZeekConnParser()
    with open(path, encoding="utf-8") as f:
        for line in f:
            ev = parser.parse_line(line)
            if ev:
                yield ev


class LogFollower:
    """Non-blocking reader for a growing Zeek log.

    - Skips lines already in the file at startup (unless from_start=True), but still reads the
      TSV header so later lines can be parsed. Stops old scans re-alerting when the agent starts.
    - Survives Zeek's hourly rotation (file renamed, new conn.log created) and truncation:
      drains the old file, then reopens the path and reads the new file from its start.
    - Buffers half-written lines until Zeek finishes writing them.
    """

    def __init__(self, path: str, from_start: bool = False) -> None:
        self.path = path
        self._fh = None
        self._ino = None
        self._parser = ZeekConnParser()
        self._partial = b""
        self._open()
        if self._fh is not None and not from_start:
            self._read_available()  # learn header, discard existing events

    def _open(self) -> None:
        try:
            self._fh = open(self.path, "rb")
        except FileNotFoundError:
            self._fh = None
            return
        self._ino = os.fstat(self._fh.fileno()).st_ino
        self._parser = ZeekConnParser()
        self._partial = b""

    def _read_available(self) -> list[ConnectionEvent]:
        events = []
        while True:
            chunk = self._fh.readline()
            if not chunk:
                break
            self._partial += chunk
            if not self._partial.endswith(b"\n"):
                break  # line still being written; finish it on the next poll
            ev = self._parser.parse_line(self._partial.decode("utf-8", errors="replace"))
            self._partial = b""
            if ev:
                events.append(ev)
        return events

    def poll(self) -> list[ConnectionEvent]:
        if self._fh is None:  # file did not exist yet (or vanished before we opened it)
            self._open()
            if self._fh is None:
                return []
        events = self._read_available()
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return events  # mid-rotation: keep the old handle, check again next poll
        if st.st_ino != self._ino or st.st_size < self._fh.tell():
            events += self._read_available()  # drain anything left in the old file
            self._fh.close()
            self._open()
            if self._fh is not None:
                events += self._read_available()
        return events

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()


def follow_file(path: str, poll_seconds: float = 1.0, from_start: bool = False) -> Iterator[ConnectionEvent]:
    """Like `tail -F`: yields new events as Zeek appends them, across log rotations."""
    follower = LogFollower(path, from_start=from_start)
    try:
        while True:
            events = follower.poll()
            yield from events
            if not events:
                time.sleep(poll_seconds)
    finally:
        follower.close()
