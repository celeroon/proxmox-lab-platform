"""FINS outstation simulating an Omron PLC on a packaging line (one CIO bit
for the conveyor motor, one DM word for the item count).

Standalone run (production / systemd):
    python3 fins_server.py --host 0.0.0.0 --port 9600

Threaded TCP server (plain socket + threading, like dnp3_server.py — no
library dictates a style here since the protocol is hand-rolled). Each
connection does its own FINS/TCP node-address handshake, then serves
MEMORY AREA READ/WRITE requests against the shared conveyor state.
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import threading
import time

from fins_logic import (
    CIO_MOTOR_ADDRESS,
    CMD_CONTROLLER_DATA_READ,
    CMD_FILE_NAME_READ,
    CMD_SINGLE_FILE_READ,
    CONTROLLER_MODEL,
    CONTROLLER_VERSION,
    DM_ITEM_COUNT_ADDRESS,
    EXPANSION_DM_SIZE,
    IOM_SIZE,
    KIND_MEMORY_CARD_FLASH,
    MEMORY_AREA_CIO_BIT,
    MEMORY_AREA_DM_WORD,
    MEMORY_CARD_FILES,
    MEMORY_CARD_SIZE_KB,
    MEMORY_CARD_TOTAL_CAPACITY,
    MEMORY_CARD_UNUSED_CAPACITY,
    MEMORY_CARD_VOLUME_LABEL,
    NUM_DM_WORDS,
    NUM_STEP_TRANSITIONS,
    PROGRAM_AREA_SIZE_KW,
    TIMER_COUNTER_SIZE,
    TRACE_FILE_NAME,
    build_trace_file_content,
    next_item_count,
)
from fins_protocol import (
    CMD_MEMORY_AREA_READ,
    CMD_MEMORY_AREA_WRITE,
    END_CODE_NORMAL,
    TCP_CMD_CLIENT_NODE_ADDR,
    TCP_CMD_FRAME,
    build_command_frame,
    build_controller_data_read_response_data,
    build_file_name_read_response_data,
    build_fins_header,
    build_read_response_data,
    build_server_node_response,
    build_single_file_read_response_data,
    build_write_response_data,
    encode_fins_datetime,
    parse_command_frame,
    parse_fins_header,
    parse_memory_area_read_data,
    parse_single_file_read_request_data,
    recv_tcp_frame,
    wrap_tcp_frame,
)

log = logging.getLogger("fins_server")

SERVER_NODE = 1
NEXT_CLIENT_NODE = 2  # only one client expected at a time in this lab


class Conveyor:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.motor_running = False
        self.item_count = 0

    def tick(self) -> None:
        with self.lock:
            self.item_count = next_item_count(self.item_count, self.motor_running)

    def read_motor(self) -> bool:
        with self.lock:
            return self.motor_running

    def write_motor(self, value: bool) -> None:
        with self.lock:
            self.motor_running = value

    def read_item_count(self) -> int:
        with self.lock:
            return self.item_count

    def write_item_count(self, value: int) -> None:
        with self.lock:
            self.item_count = value & 0xFFFF


def _file_content(file_name: str, conveyor: Conveyor) -> bytes:
    """Canned content for the simulated memory-card files. TRACE001.CSV
    reflects live conveyor state; CONVEYOR.OBJ's binary content isn't
    modeled -- it's a placeholder blob, only its *name* matters for the
    FILE NAME READ listing."""
    if file_name.strip() == TRACE_FILE_NAME:
        return build_trace_file_content(conveyor.read_item_count(), conveyor.read_motor())
    return b"\x00" * 64


def _handle_client(conn: socket.socket, addr, conveyor: Conveyor) -> None:
    log.info("master connected from %s", addr)
    client_node = NEXT_CLIENT_NODE
    try:
        command, _error_code, payload = recv_tcp_frame(conn)
        if command != TCP_CMD_CLIENT_NODE_ADDR:
            log.info("unexpected first frame (command=%d), dropping connection", command)
            return
        conn.sendall(wrap_tcp_frame(1, build_server_node_response(client_node, SERVER_NODE)))

        while True:
            try:
                command, _error_code, payload = recv_tcp_frame(conn)
            except ConnectionError:
                break
            if command != TCP_CMD_FRAME:
                continue

            is_response, dna, da1, da2, sna, sa1, sa2, sid = parse_fins_header(payload)
            command_code, data = parse_command_frame(payload[10:])

            if command_code == CMD_MEMORY_AREA_READ:
                area_code, address, bit, count = parse_memory_area_read_data(data)
                if area_code == MEMORY_AREA_CIO_BIT and address == CIO_MOTOR_ADDRESS:
                    values = bytes([1 if conveyor.read_motor() else 0])
                elif area_code == MEMORY_AREA_DM_WORD and address == DM_ITEM_COUNT_ADDRESS:
                    values = struct.pack(">H", conveyor.read_item_count())
                else:
                    values = b""
                resp_data = build_read_response_data(END_CODE_NORMAL, values)

            elif command_code == CMD_MEMORY_AREA_WRITE:
                area_code, address, bit, count = parse_memory_area_read_data(data)
                values = data[6:]
                if area_code == MEMORY_AREA_CIO_BIT and address == CIO_MOTOR_ADDRESS:
                    conveyor.write_motor(bool(values[0]))
                    log.info("WRITE motor -> %s", conveyor.read_motor())
                elif area_code == MEMORY_AREA_DM_WORD and address == DM_ITEM_COUNT_ADDRESS:
                    conveyor.write_item_count(struct.unpack(">H", values[0:2])[0])
                    log.info("WRITE item_count -> %d", conveyor.read_item_count())
                resp_data = build_write_response_data(END_CODE_NORMAL)

            elif command_code == CMD_CONTROLLER_DATA_READ:
                resp_data = build_controller_data_read_response_data(
                    END_CODE_NORMAL,
                    CONTROLLER_MODEL,
                    CONTROLLER_VERSION,
                    PROGRAM_AREA_SIZE_KW,
                    IOM_SIZE,
                    NUM_DM_WORDS,
                    TIMER_COUNTER_SIZE,
                    EXPANSION_DM_SIZE,
                    NUM_STEP_TRANSITIONS,
                    KIND_MEMORY_CARD_FLASH,
                    MEMORY_CARD_SIZE_KB,
                )
                log.info("CONTROLLER DATA READ -> model=%r version=%r", CONTROLLER_MODEL, CONTROLLER_VERSION)

            elif command_code == CMD_FILE_NAME_READ:
                date_time = encode_fins_datetime(46, 7, 5, 12, 0, 0)  # 2026-07-05 12:00:00
                files = [(name, date_time, capacity) for name, capacity in MEMORY_CARD_FILES]
                resp_data = build_file_name_read_response_data(
                    END_CODE_NORMAL,
                    MEMORY_CARD_VOLUME_LABEL,
                    date_time,
                    MEMORY_CARD_TOTAL_CAPACITY,
                    MEMORY_CARD_UNUSED_CAPACITY,
                    files,
                )
                log.info("FILE NAME READ -> %d files on volume %r", len(files), MEMORY_CARD_VOLUME_LABEL)

            elif command_code == CMD_SINGLE_FILE_READ:
                _disk_no, file_name, file_position, data_length = parse_single_file_read_request_data(data)
                content = _file_content(file_name, conveyor)
                chunk = content[file_position : file_position + data_length] if data_length else content[file_position:]
                resp_data = build_single_file_read_response_data(END_CODE_NORMAL, len(content), file_position, chunk)
                log.info("SINGLE FILE READ %r -> %d bytes", file_name.strip(), len(chunk))

            else:
                continue

            resp_header = build_fins_header(
                is_response=True, dna=sna, da1=sa1, da2=sa2, sna=dna, sa1=da1, sa2=da2, sid=sid
            )
            resp_frame = resp_header + build_command_frame(command_code, resp_data)
            conn.sendall(wrap_tcp_frame(TCP_CMD_FRAME, resp_frame))
    finally:
        conn.close()
        log.info("master disconnected from %s", addr)


def _tick_loop(conveyor: Conveyor, tick_seconds: float) -> None:
    while True:
        time.sleep(tick_seconds)
        conveyor.tick()
        log.info("item_count=%d motor_running=%s", conveyor.read_item_count(), conveyor.read_motor())


def run(host: str, port: int, tick_seconds: float) -> None:
    conveyor = Conveyor()
    threading.Thread(target=_tick_loop, args=(conveyor, tick_seconds), daemon=True).start()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    log.info("FINS outstation listening on %s:%d", host, port)
    try:
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=_handle_client, args=(conn, addr, conveyor), daemon=True).start()
    finally:
        server_sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="FINS packaging-line conveyor simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9600)
    parser.add_argument("--tick-seconds", type=float, default=1.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    run(args.host, args.port, args.tick_seconds)


if __name__ == "__main__":
    main()
