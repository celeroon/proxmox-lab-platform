"""Pure simulation logic + DNP3 wire-format constants for the substation breaker process.

No network/IO here on purpose — imported by the protocol module, server, client,
and the unit tests, so the physics and constants are verified once.
"""

from __future__ import annotations

import random

# --- DNP3 link-layer constants ---
START_BYTES = b"\x05\x64"
MASTER_CONTROL = 0xC4  # DIR=1,PRM=1,FCB=0,FCV=0,FUNC=4 (UNCONFIRMED_USER_DATA)
OUTSTATION_CONTROL = 0x44  # DIR=0,PRM=1,FCB=0,FCV=0,FUNC=4

# --- DNP3 application-layer function codes ---
FC_READ = 1
FC_SELECT = 3
FC_OPERATE = 4
FC_DIRECT_OPERATE = 5
FC_COLD_RESTART = 13
FC_RESPONSE = 0x81

# --- Object groups/variations used (deliberately minimal subset) ---
GROUP_BINARY_OUTPUT_STATUS = 10
VAR_BINARY_OUTPUT_STATUS = 2
GROUP_ANALOG_INPUT = 30
VAR_ANALOG_INPUT_32 = 1
GROUP_CROB = 12
VAR_CROB = 1
GROUP_CLASS_DATA = 60  # used in READ requests to mean "Class N data"
GROUP_TIME_DELAY = 52
VAR_TIME_DELAY_FINE = 2

QUAL_ALL_OBJECTS = 0x06
QUAL_8BIT_START_STOP = 0x00
QUAL_8BIT_COUNT_NO_RANGE = 0x07

# CROB control codes. The control_code byte encodes TWO sub-fields, not one:
# bits 0-3 = operation type (0=Nul,1=Pulse-On,2=Pulse-Off,3=Latch-On,4=Latch-Off)
# and bits 6-7 = Trip-Close Code/TCC (0=Nul,1=Close,2=Trip). A real DNP3 master
# sets BOTH alongside each other. The original encoding here only ever set the
# operation-type nibble (0x03/0x04) and left TCC at 0 (Nul) for every request —
# confirmed empirically 2026-07-05: 0 of 943 real dnp3_control.log documents
# had `trip_control_code` populated, which is exactly why Malcolm's built-in
# "DNP3 - Control Overview" dashboard (whose deepest aggregation level is
# `zeek.dnp3_control.trip_control_code`) showed no data despite plenty of
# other dnp3_control activity. Fixed to combine both sub-fields correctly.
CROB_CLOSE = 0x43  # Latch On (0x03) + TCC=Close (0x40)
CROB_TRIP = 0x84  # Latch Off (0x04) + TCC=Trip (0x80)

# IIN1 flags
IIN1_DEVICE_RESTART = 0x80

# Point indices — one breaker, one current sensor
BREAKER_INDEX = 0
CURRENT_INDEX = 0

SELECT_VALIDITY_SECONDS = 5.0
REBOOT_SECONDS = 5.0


def crc16_dnp3(data: bytes) -> int:
    """DNP3's CRC-16: poly 0xA6BC (reflected), init 0, final one's-complement.
    Verified against the official check value (0xEA82 for b'123456789')."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc = crc >> 1
    return (~crc) & 0xFFFF


def next_line_current(breaker_closed: bool, jitter: float | None = None) -> float:
    """Pure function: realistic line current reading. ~0A open, ~noisy when closed."""
    if not breaker_closed:
        return 0.0
    noise = jitter if jitter is not None else random.uniform(-2.0, 2.0)
    return 40.0 + noise
