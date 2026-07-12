"""Shared parsing/rendering helpers for the profinet-server/profinet-client
TUIs.

Pure functions only — no I/O, no terminal/rich dependency — so they can be
unit tested without a live log file or a terminal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

_ATTEMPT_RE = re.compile(r"AR-Connect attempt #(?P<attempt>\d+): (?P<outcome>SUCCESS|FAILED)")
_SUCCESS_DETAIL_RE = re.compile(
    r"has_cyclic=(?P<has_cyclic>True|False|None)"
    r" input_frame_id=(?P<input_frame_id>\S+)"
    r" output_frame_id=(?P<output_frame_id>\S+)"
)
_LED_RE = re.compile(r"Profinet signal LED indication\. New state: (?P<state>\d+)")
# Matches pn_dev's own startup banner line, e.g.:
# "Network script for eth1:  Set IP 192.168.80.10   Netmask 255.255.255.0
#  Gateway 192.168.80.1   Permanent: 1   Hostname: profinet-server ..."
_STARTUP_RE = re.compile(r"Set IP (?P<ip>\S+)\s+Netmask \S+\s+Gateway \S+.*?Hostname:\s*(?P<hostname>\S+)")


@dataclass
class ConnectAttempt:
    attempt: int
    success: bool
    has_cyclic: Optional[bool]
    input_frame_id: Optional[str]
    output_frame_id: Optional[str]
    reason: Optional[str]  # set when success is False


def parse_client_log_line(line: str) -> Optional[ConnectAttempt]:
    """Extract a ConnectAttempt from one profinet_client.py poller log line.

    Returns None if the line doesn't match an "AR-Connect attempt #N:" line
    (e.g. a DCP-resolve-failure line, or blank/startup output)."""
    m = _ATTEMPT_RE.search(line)
    if not m:
        return None
    attempt = int(m.group("attempt"))
    success = m.group("outcome") == "SUCCESS"
    if not success:
        reason = line.split("FAILED", 1)[1].strip(" -")
        return ConnectAttempt(
            attempt=attempt,
            success=False,
            has_cyclic=None,
            input_frame_id=None,
            output_frame_id=None,
            reason=reason or None,
        )
    detail = _SUCCESS_DETAIL_RE.search(line)
    if not detail:
        return ConnectAttempt(attempt, True, None, None, None, None)
    has_cyclic_raw = detail.group("has_cyclic")
    return ConnectAttempt(
        attempt=attempt,
        success=True,
        has_cyclic=(has_cyclic_raw == "True") if has_cyclic_raw != "None" else None,
        input_frame_id=detail.group("input_frame_id"),
        output_frame_id=detail.group("output_frame_id"),
        reason=None,
    )


def parse_server_led_line(line: str) -> Optional[int]:
    """Extract the new LED state (0/1) from a pn_dev signal-indication line.

    Returns None for any other pn_dev log line (startup banner, etc.)."""
    m = _LED_RE.search(line)
    if not m:
        return None
    return int(m.group("state"))


@dataclass
class ServerIdentity:
    ip: str
    hostname: str


def parse_server_startup_line(line: str) -> Optional[ServerIdentity]:
    """Extract IP/hostname from pn_dev's own "Network script for ethX: ..."
    startup banner line. Returns None for any other line."""
    m = _STARTUP_RE.search(line)
    if not m:
        return None
    return ServerIdentity(ip=m.group("ip"), hostname=m.group("hostname"))


def success_ratio(outcomes: Iterable[bool]) -> float:
    """Fraction of True values in outcomes; 0.0 for an empty sequence."""
    values = list(outcomes)
    if not values:
        return 0.0
    return sum(1 for v in values if v) / len(values)


# ASCII-only, not Unicode block-height chars — some terminal fonts don't have
# glyphs for U+2581-2588 and silently fall back to a generic replacement shape
# (e.g. a uniform diamond) for all of them, making the sparkline useless since
# every value looks identical. Confirmed live 2026-07-03 (see modbus TUI).
_SPARK_CHARS = " .:-=+*#%@"


def sparkline(values: Iterable[float], lo: float = 0.0, hi: float = 100.0) -> str:
    """Render a sequence of values as an ASCII sparkline."""
    values = list(values)
    if not values:
        return ""
    span = max(hi - lo, 1e-9)
    chars = []
    for v in values:
        frac = min(1.0, max(0.0, (v - lo) / span))
        idx = int(round(frac * (len(_SPARK_CHARS) - 1)))
        chars.append(_SPARK_CHARS[idx])
    return "".join(chars)
