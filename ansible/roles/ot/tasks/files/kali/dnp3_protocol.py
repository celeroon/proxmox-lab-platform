"""Minimal hand-rolled DNP3 wire protocol — data link + transport + application
layers. Duplicated from ansible/roles/ot/tasks/files/dnp3/dnp3_protocol.py —
see dnp3_logic.py's module docstring in this same directory for why.
"""

from __future__ import annotations

import struct

from dnp3_logic import (
    BREAKER_INDEX,
    CURRENT_INDEX,
    GROUP_ANALOG_INPUT,
    GROUP_BINARY_OUTPUT_STATUS,
    GROUP_CLASS_DATA,
    GROUP_CROB,
    GROUP_TIME_DELAY,
    QUAL_8BIT_COUNT_NO_RANGE,
    QUAL_8BIT_START_STOP,
    QUAL_ALL_OBJECTS,
    START_BYTES,
    VAR_ANALOG_INPUT_32,
    VAR_BINARY_OUTPUT_STATUS,
    VAR_CROB,
    VAR_TIME_DELAY_FINE,
    crc16_dnp3,
)

FC_READ = 1
FC_SELECT = 3
FC_OPERATE = 4
FC_DIRECT_OPERATE = 5
FC_COLD_RESTART = 13
FC_RESPONSE = 0x81


# --- data link layer ---

def _chunk_with_crc(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        out += block
        out += struct.pack("<H", crc16_dnp3(block))
    return bytes(out)


def _dechunk_with_crc(wire_body: bytes, payload_len: int) -> bytes:
    out = bytearray()
    pos = 0
    remaining = payload_len
    while remaining > 0:
        block_len = min(16, remaining)
        block = wire_body[pos : pos + block_len]
        crc_expected = struct.unpack("<H", wire_body[pos + block_len : pos + block_len + 2])[0]
        crc_actual = crc16_dnp3(block)
        if crc_expected != crc_actual:
            raise ValueError(f"DNP3 block CRC mismatch: expected {crc_expected:#x} got {crc_actual:#x}")
        out += block
        pos += block_len + 2
        remaining -= block_len
    return bytes(out)


def wrap_frame(control: int, dest: int, src: int, user_data: bytes) -> bytes:
    length = 5 + len(user_data)  # control(1) + dest(2) + src(2) + user_data
    header_body = struct.pack("<BBHH", length, control, dest, src)
    # CRC covers the sync bytes too (8 bytes total) -- see dnp3_protocol.py's
    # copy in ansible/roles/ot/tasks/files/dnp3/ for the full story (confirmed
    # empirically against Zeek's own DNP3 analyzer 2026-07-05).
    header = START_BYTES + header_body + struct.pack("<H", crc16_dnp3(START_BYTES + header_body))
    return header + _chunk_with_crc(user_data)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while reading a DNP3 frame")
        buf += chunk
    return buf


def recv_frame(sock) -> tuple[int, int, int, bytes]:
    header = _recv_exact(sock, 10)
    if header[0:2] != START_BYTES:
        raise ValueError("bad DNP3 start bytes")
    length, control, dest, src = struct.unpack("<BBHH", header[2:8])
    crc_expected = struct.unpack("<H", header[8:10])[0]
    if crc16_dnp3(header[0:8]) != crc_expected:  # CRC scope includes sync bytes -- see wrap_frame()
        raise ValueError("bad DNP3 header CRC")
    payload_len = length - 5
    if payload_len <= 0:
        return control, dest, src, b""
    num_blocks = (payload_len + 15) // 16
    wire_body = _recv_exact(sock, payload_len + num_blocks * 2)
    return control, dest, src, _dechunk_with_crc(wire_body, payload_len)


# --- transport layer (single-segment only — our payloads are always tiny) ---

def wrap_transport(app_bytes: bytes, seq: int) -> bytes:
    return bytes([0xC0 | (seq & 0x3F)]) + app_bytes  # FIR=1,FIN=1,SEQ


def unwrap_transport(data: bytes) -> bytes:
    return data[1:]


# --- application objects ---

def encode_binary_output_status(closed: bool) -> bytes:
    flags = 0x01 | (0x80 if closed else 0x00)  # bit0=ONLINE, bit7=STATE
    return struct.pack(
        "<BBBBBB",
        GROUP_BINARY_OUTPUT_STATUS,
        VAR_BINARY_OUTPUT_STATUS,
        QUAL_8BIT_START_STOP,
        BREAKER_INDEX,
        BREAKER_INDEX,
        flags,
    )


def decode_binary_output_status(data: bytes) -> bool:
    flags = data[5]
    return bool(flags & 0x80)


def encode_analog_input(current_amps: float) -> bytes:
    header = struct.pack(
        "<BBBBB", GROUP_ANALOG_INPUT, VAR_ANALOG_INPUT_32, QUAL_8BIT_START_STOP, CURRENT_INDEX, CURRENT_INDEX
    )
    return header + struct.pack("<Bi", 0x01, int(round(current_amps * 100)))  # flags + fixed-point x100


def decode_analog_input(data: bytes) -> float:
    _flags, raw = struct.unpack("<Bi", data[5:10])
    return raw / 100.0


def encode_full_status(closed: bool, current_amps: float) -> bytes:
    return encode_binary_output_status(closed) + encode_analog_input(current_amps)


def decode_full_status(obj_bytes: bytes) -> tuple[bool, float]:
    closed = decode_binary_output_status(obj_bytes[0:6])
    current = decode_analog_input(obj_bytes[6:16])
    return closed, current


def encode_crob(control_code: int, count: int = 1, on_time: int = 100, off_time: int = 100, status: int = 0) -> bytes:
    header = struct.pack("<BBBBB", GROUP_CROB, VAR_CROB, QUAL_8BIT_START_STOP, BREAKER_INDEX, BREAKER_INDEX)
    return header + struct.pack("<BBIIB", control_code, count, on_time, off_time, status)


def decode_crob(data: bytes) -> tuple[int, int]:
    """Returns (control_code, status). Object header is 5 bytes, CROB data 11 bytes."""
    control_code, _count, _on, _off, status = struct.unpack("<BBIIB", data[5:16])
    return control_code, status


def encode_class_read(class_num: int) -> bytes:
    return struct.pack("<BBB", GROUP_CLASS_DATA, class_num + 1, QUAL_ALL_OBJECTS)


def encode_time_delay(seconds: int) -> bytes:
    header = struct.pack("<BBB", GROUP_TIME_DELAY, VAR_TIME_DELAY_FINE, QUAL_8BIT_COUNT_NO_RANGE)
    return header + struct.pack("<BH", 1, seconds)


# --- application fragment builders ---

def build_app_request(function_code: int, seq: int, object_bytes: bytes = b"") -> bytes:
    app_control = 0xC0 | (seq & 0x0F)  # FIR=1,FIN=1,CON=0,UNS=0,SEQ
    return struct.pack("<BB", app_control, function_code) + object_bytes


def build_app_response(seq: int, iin1: int, iin2: int, object_bytes: bytes = b"") -> bytes:
    app_control = 0xC0 | (seq & 0x0F)
    return struct.pack("<BBBB", app_control, FC_RESPONSE, iin1, iin2) + object_bytes


def parse_app_header(app_bytes: bytes) -> tuple[int, int]:
    """Returns (function_code, object_bytes_offset) for a request fragment."""
    return app_bytes[1], 2


def parse_response_header(app_bytes: bytes) -> tuple[int, int, bytes]:
    """Returns (iin1, iin2, object_bytes) for a response fragment."""
    iin1, iin2 = app_bytes[2], app_bytes[3]
    return iin1, iin2, app_bytes[4:]
