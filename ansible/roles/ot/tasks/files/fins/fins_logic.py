"""Pure simulation logic + FINS wire-format constants for the packaging-line
conveyor process. No network/IO here on purpose — imported by the protocol
module, server, client, and the unit tests, so the physics and constants are
verified once.

FINS has no pip-installable library that provides BOTH client and server
roles — every public Python FINS library found (`fins`, `pyfins`,
`omron_fins`, `fins-driver`) is a CLIENT ONLY, meant to talk to a real Omron
PLC, the same situation DNP3 was in. So this wire protocol is hand-rolled
from the public FINS/TCP frame format (cross-checked against Wireshark's own
`packet-omron-fins.c` dissector source, not just informal blog descriptions
— see fins_protocol.py's module docstring for the specific fields verified
this way and the ones still UNVERIFIED against a real Zeek capture).
"""

from __future__ import annotations

# --- FINS/TCP wrapper header ---
FINS_TCP_MAGIC = b"FINS"
TCP_CMD_CLIENT_NODE_ADDR = 0  # client -> server: "here is the node address I want"
TCP_CMD_SERVER_NODE_ADDR = 1  # server -> client: "you are assigned this node address"
TCP_CMD_FRAME = 2  # wraps an actual FINS command/response frame

# --- FINS command header (10 bytes, all fields 1 byte) ---
ICF_COMMAND = 0x80  # bit7=1 (response required), rest 0
ICF_RESPONSE = 0xC0  # bit7=1, bit6=1 (this IS the response)
RSV = 0x00
GCT = 0x02

# --- Memory area codes (standard Omron FINS area code table) ---
MEMORY_AREA_DM_WORD = 0x82
MEMORY_AREA_CIO_BIT = 0x30

# --- Command codes ---
CMD_MEMORY_AREA_READ = 0x0101
CMD_MEMORY_AREA_WRITE = 0x0102
CMD_CONTROLLER_DATA_READ = 0x0501  # verified against Wireshark's packet-omron-fins.c
CMD_FILE_NAME_READ = 0x2201        # AND cisagov/icsnpp-omron-fins's spicy grammar --
CMD_SINGLE_FILE_READ = 0x2202      # see fins_protocol.py's module docstring.

END_CODE_NORMAL = 0x0000

# --- Simulated packaging-line conveyor: one CIO bit (motor), one DM word (item count) ---
CIO_MOTOR_ADDRESS = 0  # CIO 0.00
DM_ITEM_COUNT_ADDRESS = 0  # D0

ITEM_COUNT_MAX = 0xFFFF  # DM word wraps at 16 bits, matching real PLC word width


def next_item_count(item_count: int, motor_running: bool) -> int:
    """Pure function: conveyor counter advances by 1 per tick while the motor
    runs, wrapping at the 16-bit word boundary like a real DM word would."""
    if not motor_running:
        return item_count
    return (item_count + 1) % (ITEM_COUNT_MAX + 1)


# --- Simulated PLC identity, for CONTROLLER DATA READ (0x0501) ---
# A plausible real Omron model/version pair -- cosmetic, no functional meaning.
CONTROLLER_DATA_SELECTOR_MODEL = 0x00
CONTROLLER_MODEL = "CJ2M-CPU34"
CONTROLLER_VERSION = "2.06"
PROGRAM_AREA_SIZE_KW = 60
IOM_SIZE = 1
NUM_DM_WORDS = 32768
TIMER_COUNTER_SIZE = 1
EXPANSION_DM_SIZE = 0
NUM_STEP_TRANSITIONS = 0
KIND_MEMORY_CARD_FLASH = 2
MEMORY_CARD_SIZE_KB = 512

# --- Simulated memory-card contents, for FILE NAME READ (0x2201) / SINGLE FILE
# READ (0x2202) -- a program backup plus a data-trace log, both plausible
# things to find on a real Omron PLC's memory card.
MEMORY_CARD_DISK_NO = 0
MEMORY_CARD_VOLUME_LABEL = "CONVEYORPLC"
MEMORY_CARD_TOTAL_CAPACITY = 512 * 1024
MEMORY_CARD_UNUSED_CAPACITY = 480 * 1024
MEMORY_CARD_FILES = (
    ("CONVEYOR.OBJ", 8192),
    ("TRACE001.CSV", 256),
)
TRACE_FILE_NAME = "TRACE001.CSV"


def build_trace_file_content(item_count: int, motor_running: bool) -> bytes:
    """Pure function: renders the simulated TRACE001.CSV memory-card file --
    a one-row data-trace snapshot, the kind of file a real HMI would pull off
    the PLC's memory card for offline analysis."""
    return f"item_count,motor_running\n{item_count},{motor_running}\n".encode("ascii")
