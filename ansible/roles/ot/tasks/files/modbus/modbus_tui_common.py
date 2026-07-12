"""Shared parsing/rendering helpers for the modbus-server/modbus-client TUIs.

Pure functions only — no I/O, no terminal/rich dependency — so they can be
unit tested without a live log file or a terminal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

_LINE_RE = re.compile(
    r"level=(?P<level>[\d.]+)%"
    r"(?:\s+pump_on=(?P<pump_on>True|False))?"
    r"(?:\s+high_alarm=(?P<high_alarm>True|False))?"
    r"(?:\s+threshold=(?P<threshold>[\d.]+)%)?"
)


@dataclass
class Reading:
    level: float
    pump_on: Optional[bool]
    high_alarm: Optional[bool]
    threshold: Optional[float]


def parse_log_line(line: str) -> Optional[Reading]:
    """Extract a Reading from one modbus-server/modbus-client log line.

    Returns None if the line doesn't contain a "level=" field (e.g. a
    startup/shutdown log line unrelated to a poll/tick).
    """
    m = _LINE_RE.search(line)
    if not m:
        return None
    return Reading(
        level=float(m.group("level")),
        pump_on=(m.group("pump_on") == "True") if m.group("pump_on") else None,
        high_alarm=(m.group("high_alarm") == "True") if m.group("high_alarm") else None,
        threshold=float(m.group("threshold")) if m.group("threshold") else None,
    )


# ASCII-only, not Unicode block-height chars: some terminal fonts don't have
# glyphs for U+2581-2588 and silently fall back to a generic replacement shape
# (e.g. a uniform diamond) for all of them, making the sparkline useless since
# every value looks identical. Confirmed live 2026-07-03.
_SPARK_CHARS = " .:-=+*#%@"


def sparkline(values: Iterable[float], lo: float = 0.0, hi: float = 100.0) -> str:
    """Render a sequence of values (0-100 scale by default) as a unicode sparkline."""
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


def bar(level: float, width: int = 40, lo: float = 0.0, hi: float = 100.0) -> str:
    """Render a horizontal fill bar, e.g. '[████████░░░░░░░░░░░░]'."""
    span = max(hi - lo, 1e-9)
    frac = min(1.0, max(0.0, (level - lo) / span))
    filled = int(round(frac * width))
    return "[" + ("█" * filled) + ("░" * (width - filled)) + "]"
