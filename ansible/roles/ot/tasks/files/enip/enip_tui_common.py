"""Shared parsing/rendering helpers for the enip-server/enip-client TUIs.

Pure functions only — no I/O, no terminal/rich dependency — so they can be
unit tested without a live log file or a terminal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

# enip_server.py logs "Sensor1=True Solenoid1=False" (tag names);
# enip_client.py logs "sensor_active=True solenoid_on=False" (attribute
# names) -- both always log the pair together, so one regex covers both.
_LINE_RE = re.compile(
    r"(?:Sensor1|sensor_active)=(?P<sensor>True|False)"
    r"\s+(?:Solenoid1|solenoid_on)=(?P<solenoid>True|False)"
)


@dataclass
class Reading:
    sensor_active: bool
    solenoid_on: bool


def parse_log_line(line: str) -> Optional[Reading]:
    """Extract a Reading from one enip-server/enip-client log line.

    Returns None if the line doesn't contain a Sensor1/Solenoid1 pair (e.g. a
    startup/shutdown log line).
    """
    m = _LINE_RE.search(line)
    if not m:
        return None
    return Reading(
        sensor_active=m.group("sensor") == "True",
        solenoid_on=m.group("solenoid") == "True",
    )


# ASCII-only, not Unicode block-height chars — some terminal fonts don't have
# glyphs for U+2581-2588 and silently fall back to a generic replacement shape
# (e.g. a uniform diamond) for all of them, making the sparkline useless since
# every value looks identical. Confirmed live 2026-07-03 (see modbus TUI).
_SPARK_CHARS = " .:-=+*#%@"


def sparkline(values: Iterable[float], lo: float = 0.0, hi: float = 1.0) -> str:
    """Render a sequence of values as an ASCII sparkline. Default lo/hi=0/1
    suits the boolean sensor-state history this module renders."""
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
