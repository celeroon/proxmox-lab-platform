"""Pure simulation logic for the EtherNet/IP-CIP sensor+solenoid rack.

No network/IO here on purpose — imported by both enip_server.py and the unit tests.
"""

from __future__ import annotations

TAG_SENSOR = "Sensor1"
TAG_SOLENOID = "Solenoid1"
TOGGLE_EVERY_N_TICKS = 5


def should_toggle_sensor(tick_count: int, period: int = TOGGLE_EVERY_N_TICKS) -> bool:
    return tick_count > 0 and tick_count % period == 0


def desired_solenoid_state(sensor_active: bool) -> bool:
    """The interlock: solenoid mirrors the sensor. Trivial on purpose — the
    interesting part of this protocol is the CIP read/write mechanics and the
    attack effects, not the physics."""
    return sensor_active
