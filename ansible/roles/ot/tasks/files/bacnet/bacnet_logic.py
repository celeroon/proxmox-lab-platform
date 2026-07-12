"""Pure simulation logic for the BACnet HVAC zone.

No network/IO here on purpose — imported by both bacnet_server.py and the unit
tests. The thermostat's hysteresis control loop runs autonomously on the
server (the simulated RTU controller), same as a real local thermostat — the
client is purely supervisory (reads temperature, occasionally adjusts the
setpoint), it never drives UnitRunning directly itself.
"""

from __future__ import annotations

TAG_TEMPERATURE = "Temperature"
TAG_SETPOINT = "Setpoint"
TAG_UNIT_RUNNING = "UnitRunning"

TEMPERATURE_INSTANCE = 0
SETPOINT_INSTANCE = 2
UNIT_RUNNING_INSTANCE = 1

DEADBAND = 1.0
HEATING_RATE = 0.5  # degrees/tick while the unit runs
PASSIVE_LOSS_RATE = 0.2  # degrees/tick drift toward ambient while off
AMBIENT = 15.0


def desired_unit_running(temp: float, setpoint: float, currently_running: bool) -> bool:
    """Thermostat hysteresis with a deadband — avoids on/off chatter right at
    the setpoint. Pure, deterministic."""
    if temp < setpoint - DEADBAND:
        return True
    if temp > setpoint + DEADBAND:
        return False
    return currently_running


def next_temperature(temp: float, unit_running: bool) -> float:
    if unit_running:
        return temp + HEATING_RATE
    if temp > AMBIENT:
        return max(AMBIENT, temp - PASSIVE_LOSS_RATE)
    return temp
