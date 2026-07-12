"""Shared parsing/rendering helpers for the dnp3-server/dnp3-client TUIs.

Pure functions only — no I/O, no terminal/rich dependency — so they can be
unit tested without a live log file or a terminal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

_LINE_RE = re.compile(
    r"breaker_closed=(?P<breaker_closed>True|False)"
    r"\s+line_current=(?P<line_current>[\d.]+)A"
    r"(?:\s+in_outage=(?P<in_outage>True|False))?"
    r"(?:\s+device_restart=(?P<device_restart>True|False))?"
)


@dataclass
class Reading:
    breaker_closed: bool
    line_current: float
    in_outage: Optional[bool]  # dnp3-server only
    device_restart: Optional[bool]  # dnp3-client only


def parse_log_line(line: str) -> Optional[Reading]:
    """Extract a Reading from one dnp3-server/dnp3-client log line.

    Returns None if the line doesn't contain a "breaker_closed=" tick/poll
    field (e.g. a SELECT/OPERATE/COLD_RESTART/startup log line).
    """
    m = _LINE_RE.search(line)
    if not m:
        return None
    return Reading(
        breaker_closed=m.group("breaker_closed") == "True",
        line_current=float(m.group("line_current")),
        in_outage=(m.group("in_outage") == "True") if m.group("in_outage") else None,
        device_restart=(m.group("device_restart") == "True") if m.group("device_restart") else None,
    )


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
