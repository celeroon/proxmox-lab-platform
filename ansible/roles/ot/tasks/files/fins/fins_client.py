"""FINS master simulating an HMI monitoring the packaging-line conveyor.

Standalone run (production / systemd):
    python3 fins_client.py --host 192.168.70.10 --port 9600

Each poll opens nothing new — one persistent TCP connection for the whole
run, matching dnp3_client.py's/s7_client.py's precedent. poll_once()/
toggle_motor() are reused directly by the local round-trip test.

external_probe() added on top of the base design (there is no reference
implementation to port from for FINS — this protocol was hand-rolled directly
for this deployment) to match every other protocol pair's "ICS/IoT External
Traffic" panel demo.
"""

from __future__ import annotations

import argparse
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass

from fins_logic import (
    CIO_MOTOR_ADDRESS,
    CMD_CONTROLLER_DATA_READ,
    CMD_FILE_NAME_READ,
    CMD_SINGLE_FILE_READ,
    CONTROLLER_DATA_SELECTOR_MODEL,
    DM_ITEM_COUNT_ADDRESS,
    MEMORY_AREA_CIO_BIT,
    MEMORY_AREA_DM_WORD,
    MEMORY_CARD_DISK_NO,
    TRACE_FILE_NAME,
)
from fins_protocol import (
    CMD_MEMORY_AREA_READ,
    CMD_MEMORY_AREA_WRITE,
    TCP_CMD_CLIENT_NODE_ADDR,
    TCP_CMD_FRAME,
    build_client_node_request,
    build_command_frame,
    build_controller_data_read_request_data,
    build_file_name_read_request_data,
    build_fins_header,
    build_memory_area_read_data,
    build_memory_area_write_data,
    build_single_file_read_request_data,
    parse_controller_data_read_response_data,
    parse_file_name_read_response_data,
    parse_read_response_data,
    parse_server_node_response,
    parse_single_file_read_response_data,
    recv_tcp_frame,
    wrap_tcp_frame,
)

log = logging.getLogger("fins_client")

CLIENT_NODE = 2
TOGGLE_EVERY_N_POLLS = 10
EXTERNAL_PROBE_MIN_DELAY = 60  # 1-5 minutes, matching every other protocol's external probe
EXTERNAL_PROBE_MAX_DELAY = 300

_sid_counter = 0


def _next_sid() -> int:
    global _sid_counter
    _sid_counter = (_sid_counter + 1) & 0xFF
    return _sid_counter


@dataclass
class ConveyorReading:
    item_count: int
    motor_running: bool
    producing: bool  # item_count actually advanced since the last poll


def handshake(sock: socket.socket) -> int:
    sock.sendall(wrap_tcp_frame(TCP_CMD_CLIENT_NODE_ADDR, build_client_node_request(CLIENT_NODE)))
    _command, _error_code, payload = recv_tcp_frame(sock)
    _client_node, server_node = parse_server_node_response(payload)
    return server_node


def _send_command(sock: socket.socket, server_node: int, command_code: int, data: bytes) -> bytes:
    sid = _next_sid()
    header = build_fins_header(is_response=False, dna=0, da1=server_node, da2=0, sna=0, sa1=CLIENT_NODE, sa2=0, sid=sid)
    frame = header + build_command_frame(command_code, data)
    sock.sendall(wrap_tcp_frame(TCP_CMD_FRAME, frame))
    _command, _error_code, resp_payload = recv_tcp_frame(sock)
    _resp_command_code, resp_data = resp_payload[10:12], resp_payload[12:]
    return resp_data


def read_item_count(sock: socket.socket, server_node: int) -> int:
    req = build_memory_area_read_data(MEMORY_AREA_DM_WORD, DM_ITEM_COUNT_ADDRESS, 0, 1)
    resp_data = _send_command(sock, server_node, CMD_MEMORY_AREA_READ, req)
    _end_code, values = parse_read_response_data(resp_data)
    return struct.unpack(">H", values[0:2])[0]


def read_motor(sock: socket.socket, server_node: int) -> bool:
    req = build_memory_area_read_data(MEMORY_AREA_CIO_BIT, CIO_MOTOR_ADDRESS, 0, 1)
    resp_data = _send_command(sock, server_node, CMD_MEMORY_AREA_READ, req)
    _end_code, values = parse_read_response_data(resp_data)
    return bool(values[0])


def write_motor(sock: socket.socket, server_node: int, on: bool) -> None:
    req = build_memory_area_write_data(MEMORY_AREA_CIO_BIT, CIO_MOTOR_ADDRESS, 0, 1, bytes([1 if on else 0]))
    _send_command(sock, server_node, CMD_MEMORY_AREA_WRITE, req)


def identify_plc(sock: socket.socket, server_node: int) -> None:
    """One-shot asset-identification exchange, done once right after connect
    -- the same thing a real HMI/engineering station would do to inventory a
    newly-discovered PLC, before settling into the steady-state Memory Area
    poll loop. Populates Malcolm's "Controller Model and Version" and
    "Files/Volumes" FINS dashboard panels, which stayed empty when this
    simulator only spoke Memory Area Read/Write (see fins_protocol.py's
    module docstring)."""
    req = build_controller_data_read_request_data(CONTROLLER_DATA_SELECTOR_MODEL)
    resp_data = _send_command(sock, server_node, CMD_CONTROLLER_DATA_READ, req)
    _end_code, model, version = parse_controller_data_read_response_data(resp_data)
    log.info("CONTROLLER DATA READ -> model=%r version=%r", model, version)

    req = build_file_name_read_request_data(MEMORY_CARD_DISK_NO, 0, 0)
    resp_data = _send_command(sock, server_node, CMD_FILE_NAME_READ, req)
    _end_code, volume_label, total_no_files, files = parse_file_name_read_response_data(resp_data)
    log.info("FILE NAME READ -> volume=%r files=%s", volume_label, files)

    req = build_single_file_read_request_data(MEMORY_CARD_DISK_NO, TRACE_FILE_NAME, 0, 0)
    resp_data = _send_command(sock, server_node, CMD_SINGLE_FILE_READ, req)
    _end_code, file_capacity, _file_position, file_data = parse_single_file_read_response_data(resp_data)
    log.info("SINGLE FILE READ %s -> capacity=%d bytes=%r", TRACE_FILE_NAME, file_capacity, file_data)


def poll_once(sock: socket.socket, server_node: int, previous_count: int | None) -> ConveyorReading:
    item_count = read_item_count(sock, server_node)
    motor_running = read_motor(sock, server_node)
    producing = previous_count is not None and item_count != previous_count
    return ConveyorReading(item_count=item_count, motor_running=motor_running, producing=producing)


def external_probe(ip: str, port: int) -> None:
    """Perform a real FINS read against ip:port on its own short-lived
    connection to generate external-destination ICS traffic. See module
    docstring and every other protocol pair's external_probe() here."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((ip, port))
        server_node = handshake(sock)
        read_item_count(sock, server_node)
    except Exception:
        pass  # connection/read failure is fine -- the exchange attempt is what Malcolm needs
    finally:
        sock.close()


def run(host: str, port: int, poll_seconds: float, external_probe_ip: str | None = None, external_probe_port: int = 9600) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    server_node = handshake(sock)
    identify_plc(sock, server_node)
    next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)
    try:
        previous_count: int | None = None
        poll_index = 0
        while True:
            reading = poll_once(sock, server_node, previous_count)
            log.info(
                "item_count=%d motor_running=%s producing=%s",
                reading.item_count,
                reading.motor_running,
                reading.producing,
            )
            if poll_index > 0 and poll_index % TOGGLE_EVERY_N_POLLS == 0:
                write_motor(sock, server_node, not reading.motor_running)
                log.info("routine operator toggle: motor_running -> %s", not reading.motor_running)

            if external_probe_ip and time.time() >= next_probe_time:
                external_probe(external_probe_ip, external_probe_port)
                next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)

            previous_count = reading.item_count
            poll_index += 1
            time.sleep(poll_seconds)
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="FINS HMI simulator")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=9600)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    parser.add_argument(
        "--external-probe-ip",
        default=None,
        help="IP to probe every 1-5 min to generate 'external' traffic visible in Malcolm",
    )
    parser.add_argument("--external-probe-port", type=int, default=9600)
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    run(
        args.host,
        args.port,
        args.poll_seconds,
        external_probe_ip=args.external_probe_ip,
        external_probe_port=args.external_probe_port,
    )


if __name__ == "__main__":
    main()
