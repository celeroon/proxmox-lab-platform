"""Shared parsing/rendering helpers for the bacnet-server/bacnet-client TUIs.

Pure functions only — no I/O, no terminal/rich dependency — so they can be
unit tested without a live log file or a terminal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

_LINE_RE = re.compile(
    r"Temperature=(?P<temperature>-?[\d.]+)"
    r"(?:\s+Setpoint=(?P<setpoint>-?[\d.]+))?"
    r"(?:\s+UnitRunning=(?P<unit_running>True|False))?"
    r"(?:\s+commanded_setpoint=(?P<commanded_setpoint>-?[\d.]+|-))?"
)


@dataclass
class Reading:
    temperature: float
    setpoint: Optional[float]  # bacnet-server only
    unit_running: Optional[bool]  # bacnet-server only
    commanded_setpoint: Optional[float]  # bacnet-client only


def parse_log_line(line: str) -> Optional[Reading]:
    """Extract a Reading from one bacnet-server/bacnet-client log line.

    Returns None if the line doesn't contain a "Temperature=" field (e.g. a
    startup/shutdown or "routine setpoint adjustment" log line).
    """
    m = _LINE_RE.search(line)
    if not m:
        return None
    commanded = m.group("commanded_setpoint")
    return Reading(
        temperature=float(m.group("temperature")),
        setpoint=float(m.group("setpoint")) if m.group("setpoint") else None,
        unit_running=(m.group("unit_running") == "True") if m.group("unit_running") else None,
        commanded_setpoint=float(commanded) if commanded and commanded != "-" else None,
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


def bar(value: float, width: int = 40, lo: float = 0.0, hi: float = 100.0) -> str:
    """Render a horizontal fill bar, e.g. '[████████░░░░░░░░░░░░]'."""
    span = max(hi - lo, 1e-9)
    frac = min(1.0, max(0.0, (value - lo) / span))
    filled = int(round(frac * width))
    return "[" + ("█" * filled) + ("░" * (width - filled)) + "]"
