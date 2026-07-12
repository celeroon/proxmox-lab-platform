"""Pure simulation logic for the S7comm conveyor process.

No network/IO here on purpose — imported by both s7_server.py and the unit tests.

Two independent layers of "is it actually running":
  - motor_running (DB1, byte 0, bit 0): application-level, the operator's own
    start/stop flag, written via a normal db_write — low-privilege, frequent.
  - cpu_running (server.cpu_state == CPUState.RUN): protocol-level, whether the
    PLC's program is executing at all — a S7comm administrative function
    (PLC_STOP/PLC_HOT_START), high-privilege, rare, and the thing an attacker
    abuses for T0814 Denial of Service.

Production only advances when BOTH are true — stopping the PLC halts
production regardless of what the operator's motor_running flag says, exactly
like a real S7-1200/1500 going into STOP mode.
"""

from __future__ import annotations

# --- DB1 layout (shared contract between server and client) ---
MOTOR_RUNNING_BYTE = 0
MOTOR_RUNNING_BIT = 0
ITEM_COUNT_BYTE = 2  # 4-byte dint, bytes 2-5
DB_NUMBER = 1
DB_SIZE = 10


def next_item_count(item_count: int, motor_running: bool, cpu_running: bool) -> int:
    """Advance the conveyor's item counter by one step. Pure, deterministic."""
    if motor_running and cpu_running:
        return item_count + 1
    return item_count
