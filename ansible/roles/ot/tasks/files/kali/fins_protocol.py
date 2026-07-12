"""Minimal hand-rolled FINS/TCP wire protocol — just enough to carry the
node-address handshake, MEMORY AREA READ/WRITE for one CIO bit (motor) and
one DM word (item count), plus CONTROLLER DATA READ (0x0501) and FILE NAME
READ / SINGLE FILE READ (0x2201/0x2202) for PLC-identity and memory-card
metadata (added 2026-07-05, after production traffic showed Malcolm's stock
"Controller Model and Version" and "Files/Volumes" FINS dashboard panels
sitting empty -- this simulator only spoke Memory Area Read/Write before).

VERIFIED AGAINST A REAL ZEEK CAPTURE 2026-07-05 — built from public FINS/TCP
documentation cross-checked against Wireshark's own `packet-omron-fins.c`
dissector source (not just informal blog descriptions, which disagreed with
each other on the TCP header's length-field byte order — Wireshark's own
source confirms big-endian, used here), then confirmed correct by capturing
real traffic and replaying it through `zeek -C -r` in isolation: Zeek parsed
it perfectly on the first try (`omron_fins_detail.log` fully populated,
correct memory area codes/addresses/response data, zero weirds) — unlike
DNP3, this wire format needed no fix. The gap that DID surface live (0
`omron_fins_detail` documents in the actual deployment despite continuous
traffic) turned out to be infrastructure, not protocol: malcolm-1's
`zeek-live` container held stale capture state after `switch-1` was freshly
rebuilt (new gretap tunnel) — restarting `zeek-live` fixed live ingestion
immediately. If Malcolm ever shows nothing for FINS again, restart
`zeek-live` before suspecting this wire format.

The 0x0501/0x2201/0x2202 payload layouts below were cross-checked against
TWO independent sources: Wireshark's `packet-omron-fins.c` (byte offsets/
sizes) AND `cisagov/icsnpp-omron-fins`'s actual Spicy grammar (the analyzer
Malcolm/Zeek really runs) -- both agree on field order and sizes, so the
byte counts here (92-byte Controller-Model response, 30-byte-base File Name
Read response, 12-byte-base Single File Read response) are exact, not
guessed. Still UNVERIFIED against a real Zeek capture (unlike the Memory
Area commands above) -- these were built from spec/source cross-reference
only, not confirmed by capturing real traffic and replaying it through
`zeek -C -r` yet.

Frame layout:
  FINS/TCP wrapper: magic("FINS", 4) + length(4, BE) + command(4, BE) +
    error_code(4, BE), then `length - 8` bytes of payload.
  FINS command frame (payload when command == TCP_CMD_FRAME): 10-byte FINS
    header (ICF,RSV,GCT,DNA,DA1,DA2,SNA,SA1,SA2,SID, all 1 byte each) +
    2-byte command code (BE) + command-specific data.
"""

from __future__ import annotations

import struct

from fins_logic import (
    CMD_MEMORY_AREA_READ,
    CMD_MEMORY_AREA_WRITE,
    END_CODE_NORMAL,
    FINS_TCP_MAGIC,
    GCT,
    ICF_COMMAND,
    ICF_RESPONSE,
    RSV,
    TCP_CMD_CLIENT_NODE_ADDR,
    TCP_CMD_FRAME,
)


# --- FINS/TCP wrapper ---

def wrap_tcp_frame(command: int, payload: bytes, error_code: int = 0) -> bytes:
    length = 8 + len(payload)  # counts command(4) + error_code(4) + payload
    return FINS_TCP_MAGIC + struct.pack(">III", length, command, error_code) + payload


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while reading a FINS/TCP frame")
        buf += chunk
    return buf


def recv_tcp_frame(sock) -> tuple[int, int, bytes]:
    """Returns (command, error_code, payload)."""
    header = _recv_exact(sock, 8)
    if header[0:4] != FINS_TCP_MAGIC:
        raise ValueError("bad FINS/TCP magic bytes")
    length = struct.unpack(">I", header[4:8])[0]
    rest = _recv_exact(sock, length)
    command, error_code = struct.unpack(">II", rest[0:8])
    payload = rest[8:]
    return command, error_code, payload


# --- FINS/TCP handshake payloads ---
# REAL BUG FOUND 2026-07-06 verifying the new commands against the deployed
# icsnpp-omron-fins Spicy grammar: NODE_ADDRESS_DATA_SEND_CLIENT's payload is
# a SINGLE uint32 (`dataSendClientNodeAddress`, 4 bytes) in that grammar, not
# 2 (8 bytes) -- this function sent an extra 4 bytes of padding that the
# analyzer never expected. Those 4 stray bytes get parsed as the START of the
# array's *next* element, fail the magic-bytes `&requires` check, and the
# whole TCP_Messages unit for that connection direction quietly declines
# further input (no analyzer_violation, no printed error) -- silently
# swallowing every command frame for the rest of that connection's life.
# Confirmed via a live, kernel-captured pcap of a fresh fins-client
# reconnect replayed through the exact same analyzer in isolation: only the
# very first (handshake) omron_fins_general.log record ever appeared, zero
# omron_fins_detail.log records, for ANY command code (old or new) on that
# connection -- this fix makes both come back.

def build_client_node_request(requested_node: int = 0) -> bytes:
    return struct.pack(">I", requested_node)


def build_server_node_response(client_node: int, server_node: int) -> bytes:
    return struct.pack(">II", client_node, server_node)


def parse_server_node_response(payload: bytes) -> tuple[int, int]:
    return struct.unpack(">II", payload[0:8])


# --- FINS command header (10 bytes) ---

def build_fins_header(is_response: bool, dna: int, da1: int, da2: int, sna: int, sa1: int, sa2: int, sid: int) -> bytes:
    icf = ICF_RESPONSE if is_response else ICF_COMMAND
    return struct.pack(">BBBBBBBBBB", icf, RSV, GCT, dna, da1, da2, sna, sa1, sa2, sid)


def parse_fins_header(data: bytes) -> tuple[bool, int, int, int, int, int, int, int]:
    """Returns (is_response, dna, da1, da2, sna, sa1, sa2, sid)."""
    icf, _rsv, _gct, dna, da1, da2, sna, sa1, sa2, sid = struct.unpack(">BBBBBBBBBB", data[0:10])
    is_response = bool(icf & 0x40)
    return is_response, dna, da1, da2, sna, sa1, sa2, sid


# --- MEMORY AREA READ/WRITE ---
# Command frame = FINS header (10 bytes) + command_code (2 bytes, BE) +
# command-specific data. build_command_frame() glues the last two together;
# callers prepend build_fins_header() themselves (matches parse_command_frame's
# symmetric split).

def build_command_frame(command_code: int, data: bytes) -> bytes:
    return struct.pack(">H", command_code) + data


def parse_command_frame(frame: bytes) -> tuple[int, bytes]:
    """Returns (command_code, data) for the bytes AFTER the 10-byte FINS header."""
    command_code = struct.unpack(">H", frame[0:2])[0]
    return command_code, frame[2:]


def build_memory_area_read_data(area_code: int, address: int, bit: int, count: int) -> bytes:
    return struct.pack(">BHBH", area_code, address, bit, count)


def parse_memory_area_read_data(data: bytes) -> tuple[int, int, int, int]:
    area_code, address, bit, count = struct.unpack(">BHBH", data[0:6])
    return area_code, address, bit, count


def build_memory_area_write_data(area_code: int, address: int, bit: int, count: int, values: bytes) -> bytes:
    return struct.pack(">BHBH", area_code, address, bit, count) + values


def build_read_response_data(end_code: int, values: bytes) -> bytes:
    return struct.pack(">H", end_code) + values


def parse_read_response_data(data: bytes) -> tuple[int, bytes]:
    end_code = struct.unpack(">H", data[0:2])[0]
    return end_code, data[2:]


def build_write_response_data(end_code: int) -> bytes:
    return struct.pack(">H", end_code)


def _pad_ascii(value: str, length: int) -> bytes:
    return value.encode("ascii")[:length].ljust(length, b" ")


def _unpad_ascii(value: bytes) -> str:
    return value.decode("ascii", errors="replace").rstrip()


# --- CONTROLLER DATA READ (0x0501) ---
# Response layout (94 bytes total, matching both Wireshark's
# reported_length_remaining==94 branch and icsnpp-omron-fins's 92-byte
# "Controller Model" dataToRead branch -- 92 + the 2-byte response code
# parsed separately = 94):
#   end_code(2) + controller_model(20 ASCII) + controller_version(20 ASCII)
#   + for_system_use(40, unused here) + area data(12): program_area_size(2)
#   + iom_size(1) + num_dm_words(2) + timer_counter_size(1)
#   + expansion_dm_size(1) + num_step_transitions(2) + kind_memory_card(1)
#   + memory_card_size(2)

def build_controller_data_read_request_data(selector: int) -> bytes:
    return bytes([selector])


def parse_controller_data_read_request_data(data: bytes) -> int:
    return data[0]


def build_controller_data_read_response_data(
    end_code: int,
    controller_model: str,
    controller_version: str,
    program_area_size: int,
    iom_size: int,
    num_dm_words: int,
    timer_counter_size: int,
    expansion_dm_size: int,
    num_step_transitions: int,
    kind_memory_card: int,
    memory_card_size: int,
) -> bytes:
    return (
        struct.pack(">H", end_code)
        + _pad_ascii(controller_model, 20)
        + _pad_ascii(controller_version, 20)
        + b"\x00" * 40  # "for system use" -- not meaningful in this simulator
        + struct.pack(
            ">HBHBBHBH",
            program_area_size,
            iom_size,
            num_dm_words,
            timer_counter_size,
            expansion_dm_size,
            num_step_transitions,
            kind_memory_card,
            memory_card_size,
        )
    )


def parse_controller_data_read_response_data(data: bytes) -> tuple[int, str, str]:
    """Returns (end_code, controller_model, controller_version) -- the area-data
    tail past byte 42 isn't decoded here since nothing in this simulator reads it."""
    end_code = struct.unpack(">H", data[0:2])[0]
    controller_model = _unpad_ascii(data[2:22])
    controller_version = _unpad_ascii(data[22:42])
    return end_code, controller_model, controller_version


# --- FILE NAME READ (0x2201) ---
# Request (6 bytes): disk_no(2) + beginning_file_position(2) + no_of_files(2).
# Response: end_code(2) + volume_label(12 ASCII) + date_time(4, packed BCD-ish
# bitfield per icsnpp-omron-fins's DateTime unit) + total_capacity(4) +
# unused_capacity(4) + total_no_files(2) + no_of_files bitfield(2, bit15=
# last-file flag) + per file: file_name(12 ASCII) + date_time(4) + capacity(4).

def build_file_name_read_request_data(disk_no: int, beginning_file_position: int, no_of_files: int) -> bytes:
    return struct.pack(">HHH", disk_no, beginning_file_position, no_of_files)


def parse_file_name_read_request_data(data: bytes) -> tuple[int, int, int]:
    return struct.unpack(">HHH", data[0:6])


def encode_fins_datetime(year: int, month: int, day: int, hour: int, minute: int, second: int) -> bytes:
    """4-byte bitfield matching icsnpp-omron-fins's DateTime unit: year(7
    bits)/month(4)/day(5)/hour(5)/minute(6)/second(5), MSB-first. `year` is
    years-since-1980 (e.g. 46 == 2026), not a 4-digit calendar year."""
    value = (
        (year & 0x7F) << 25
        | (month & 0xF) << 21
        | (day & 0x1F) << 16
        | (hour & 0x1F) << 11
        | (minute & 0x3F) << 5
        | (second & 0x1F)
    )
    return struct.pack(">I", value)


def build_file_name_read_response_data(
    end_code: int,
    volume_label: str,
    date_time: bytes,
    total_capacity: int,
    unused_capacity: int,
    files: list[tuple[str, bytes, int]],
    last_file: bool = True,
) -> bytes:
    """`files` is a list of (filename, date_time_bytes, capacity_bytes) --
    date_time_bytes for each file entry, same 4-byte encoding as the disk-level
    `date_time` argument (see encode_fins_datetime)."""
    total_no_files = len(files)
    no_of_files_field = (0x8000 if last_file else 0) | (total_no_files & 0x7FFF)
    out = (
        struct.pack(">H", end_code)
        + _pad_ascii(volume_label, 12)
        + date_time
        + struct.pack(">IIHH", total_capacity, unused_capacity, total_no_files, no_of_files_field)
    )
    for filename, file_date_time, capacity in files:
        out += _pad_ascii(filename, 12) + file_date_time + struct.pack(">I", capacity)
    return out


def parse_file_name_read_response_data(data: bytes) -> tuple[int, str, int, list[tuple[str, int]]]:
    """Returns (end_code, volume_label, total_no_files, [(filename, capacity), ...])."""
    end_code = struct.unpack(">H", data[0:2])[0]
    volume_label = _unpad_ascii(data[2:14])
    total_no_files = struct.unpack(">H", data[26:28])[0]
    files = []
    offset = 30
    for _ in range(total_no_files):
        entry = data[offset : offset + 20]
        filename = _unpad_ascii(entry[0:12])
        capacity = struct.unpack(">I", entry[16:20])[0]
        files.append((filename, capacity))
        offset += 20
    return end_code, volume_label, total_no_files, files


# --- SINGLE FILE READ (0x2202) ---
# Request (20 bytes): disk_no(2) + file_name(12 ASCII) + file_position(4) +
# data_length(2). Response: end_code(2) + file_capacity(4) + file_position(4)
# + data_length(2) + file_data(data_length).

def build_single_file_read_request_data(disk_no: int, file_name: str, file_position: int, data_length: int) -> bytes:
    return struct.pack(">H", disk_no) + _pad_ascii(file_name, 12) + struct.pack(">IH", file_position, data_length)


def parse_single_file_read_request_data(data: bytes) -> tuple[int, str, int, int]:
    disk_no = struct.unpack(">H", data[0:2])[0]
    file_name = _unpad_ascii(data[2:14])
    file_position, data_length = struct.unpack(">IH", data[14:20])
    return disk_no, file_name, file_position, data_length


def build_single_file_read_response_data(end_code: int, file_capacity: int, file_position: int, file_data: bytes) -> bytes:
    return struct.pack(">H", end_code) + struct.pack(">IIH", file_capacity, file_position, len(file_data)) + file_data


def parse_single_file_read_response_data(data: bytes) -> tuple[int, int, int, bytes]:
    end_code = struct.unpack(">H", data[0:2])[0]
    file_capacity, file_position, data_length = struct.unpack(">IIH", data[2:12])
    file_data = data[12 : 12 + data_length]
    return end_code, file_capacity, file_position, file_data
