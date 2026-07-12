"""Pure simulation logic for the OPC-UA generic machine.

No network/IO here on purpose — imported by both opcua_server.py and the unit
tests. Unlike BACnet's RTU, this machine has no autonomous control loop —
Status is purely a command the client/attacker sets; the server just runs the
physics (Speed) consistent with whatever Status currently says.
"""

from __future__ import annotations

NAMESPACE_URI = "http://example.org/ics-sim/machine"
OBJECT_NAME = "Machine1"
TAG_SPEED = "Speed"
TAG_STATUS = "Status"
TAG_FAULT_CODE = "FaultCode"

STATUS_STOPPED = "Stopped"
STATUS_RUNNING = "Running"
STATUS_FAULT = "Fault"

RUNNING_TARGET_SPEED = 1500.0
ACCEL_STEP = 100.0
DECEL_STEP = 150.0
SPEED_MIN = 0.0
SPEED_MAX = 2000.0


def next_speed(speed: float, running: bool, jitter: float = 0.0) -> float:
    """Pure, deterministic with jitter=0 — accelerates toward the target
    speed then random-walks around it while running; decelerates to a stop
    otherwise."""
    if not running:
        return max(SPEED_MIN, speed - DECEL_STEP)
    if speed < RUNNING_TARGET_SPEED:
        speed = min(RUNNING_TARGET_SPEED, speed + ACCEL_STEP)
    return max(SPEED_MIN, min(SPEED_MAX, speed + jitter))
