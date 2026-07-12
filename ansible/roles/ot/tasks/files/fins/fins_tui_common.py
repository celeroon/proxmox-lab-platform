"""Shared parsing/rendering helpers for the fins-server/fins-client TUIs.

Pure functions only — no I/O, no terminal/rich dependency — so they can be
unit tested without a live log file or a terminal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

_LINE_RE = re.compile(
    r"item_count=(?P<item_count>\d+)"
    r"\s+motor_running=(?P<motor_running>True|False)"
    r"(?:\s+producing=(?P<producing>True|False))?"
)


@dataclass
class Reading:
    item_count: int
    motor_running: bool
    producing: Optional[bool]  # fins-client only


def parse_log_line(line: str) -> Optional[Reading]:
    """Extract a Reading from one fins-server/fins-client log line.

    Returns None if the line doesn't contain an "item_count=" field (e.g. a
    "WRITE ...", "routine operator toggle", or startup/shutdown line)."""
    m = _LINE_RE.search(line)
    if not m:
        return None
    return Reading(
        item_count=int(m.group("item_count")),
        motor_running=m.group("motor_running") == "True",
        producing=(m.group("producing") == "True") if m.group("producing") else None,
    )


def deltas(item_counts: Iterable[int]) -> List[int]:
    """Per-step differences between consecutive item_count readings, clamped
    to >= 0 (a value reset makes the counter drop, which would otherwise show
    as a meaningless large negative spike)."""
    values = list(item_counts)
    if len(values) < 2:
        return []
    return [max(0, b - a) for a, b in zip(values, values[1:])]


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
