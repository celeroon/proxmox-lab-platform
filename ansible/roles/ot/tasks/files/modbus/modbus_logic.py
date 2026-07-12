"""Pure simulation logic for the Modbus tank+pump process.

No network/IO here on purpose — this module is imported by both modbus_server.py
(the real systemd-deployed process) and the unit tests, so the physics can be
verified without ever opening a socket.
"""

from __future__ import annotations

# --- register map (shared contract between server and client) ---
COIL_PUMP_RUN = 0           # client writes True/False to start/stop the pump
DISCRETE_HIGH_ALARM = 0     # server-set, read-only from the client's point of view
HOLDING_LEVEL = 0           # tank level, scaled x10 (0-1000 == 0.0-100.0%)
HOLDING_ALARM_THRESHOLD = 1 # also scaled x10, settable by the client

LEVEL_SCALE = 10
TANK_MIN = 0.0
TANK_MAX = 100.0

DEFAULT_FILL_RATE = 2.0     # %/sec while the pump runs
DEFAULT_DRAIN_RATE = 0.5    # %/sec passive usage, pump off
DEFAULT_ALARM_THRESHOLD = 80.0


def update_level(
    level: float,
    pump_on: bool,
    dt: float,
    fill_rate: float = DEFAULT_FILL_RATE,
    drain_rate: float = DEFAULT_DRAIN_RATE,
) -> float:
    """Advance the tank level by dt seconds. Pure function, deterministic."""
    rate = fill_rate if pump_on else -drain_rate
    return min(TANK_MAX, max(TANK_MIN, level + rate * dt))


def is_high_alarm(level: float, threshold: float) -> bool:
    return level >= threshold


def level_to_register(level: float) -> int:
    return int(round(level * LEVEL_SCALE))


def register_to_level(value: int) -> float:
    return value / LEVEL_SCALE
