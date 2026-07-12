"""Shared parsing/rendering helpers for the opcua-server/opcua-client TUIs.

Pure functions only — no I/O, no terminal/rich dependency — so they can be
unit tested without a live log file or a terminal.

Unlike every other protocol pair's TUI here, opcua-client logs an ASYMMETRIC
line per push notification (one tag at a time — "push update: Speed -> 1500.0"
or "push update: Status -> Running"), not a combined-state line like
opcua-server's per-tick "Speed=... Status=... FaultCode=...". parse_log_line()
returns a PARTIAL Reading (only the fields present in that one line are set,
others None) for both formats — callers are expected to merge successive
partial readings into a persisted current-state object, which is exactly
what opcua_server_tui.py/opcua_client_tui.py do.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

_SERVER_RE = re.compile(
    r"Speed=(?P<speed>[\d.]+)\s+Status=(?P<status>\w+)\s+FaultCode=(?P<fault>\d+)"
)
_CLIENT_PUSH_RE = re.compile(r"push update: (?P<tag>Speed|Status) -> (?P<value>.+)$")


@dataclass
class Reading:
    speed: Optional[float] = None
    status: Optional[str] = None
    fault_code: Optional[int] = None


def parse_log_line(line: str) -> Optional[Reading]:
    """Extract a (possibly partial) Reading from one opcua-server/opcua-client
    log line. Returns None if the line matches neither format (e.g. a
    "routine operator command ->" or startup/shutdown line)."""
    m = _SERVER_RE.search(line)
    if m:
        return Reading(speed=float(m.group("speed")), status=m.group("status"), fault_code=int(m.group("fault")))

    m = _CLIENT_PUSH_RE.search(line)
    if m:
        tag, value = m.group("tag"), m.group("value").strip()
        if tag == "Speed":
            try:
                return Reading(speed=float(value))
            except ValueError:
                return None
        return Reading(status=value)

    return None


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
