"""DNP3 outstation simulating a substation breaker + line-current sensor.

Standalone run (production / systemd):
    python3 dnp3_server.py --host 0.0.0.0 --port 20000

Threaded TCP server (not asyncio, not snap7-style single-thread-per-process —
plain socket + threading, since this hand-rolled protocol has no library to
dictate a style). State is protected by a simple lock since multiple clients
(legit master + attacker scripts) connect concurrently.

The COLD_RESTART response/outage behavior is the real point of the DoS attack:
after a cold restart, the outstation silently stops answering ANY request for
REBOOT_SECONDS — exactly what a real reboot looks like to a master (a timeout,
not an error response). After that window, responses carry IIN1_DEVICE_RESTART
until a real DNP3 master would clear it with a WRITE — not implemented here, so
it just stays set for the rest of the run, which is fine for a lab demo.
"""

from __future__ import annotations

import argparse
import logging
import socket
import threading
import time

from dnp3_logic import (
    CROB_CLOSE,
    IIN1_DEVICE_RESTART,
    REBOOT_SECONDS,
    SELECT_VALIDITY_SECONDS,
    next_line_current,
)
from dnp3_protocol import (
    FC_COLD_RESTART,
    FC_DIRECT_OPERATE,
    FC_OPERATE,
    FC_READ,
    FC_SELECT,
    build_app_response,
    decode_crob,
    encode_crob,
    encode_full_status,
    encode_time_delay,
    parse_app_header,
    recv_frame,
    unwrap_transport,
    wrap_frame,
    wrap_transport,
)

log = logging.getLogger("dnp3_server")

OUTSTATION_ADDR = 1
MASTER_ADDR = 2

CONTROL_SUCCESS = 0
CONTROL_NO_SELECT = 1


class Outstation:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.breaker_closed = False
        self.line_current = 0.0
        self.pending_select: tuple[int, float] | None = None
        self.restart_until = 0.0
        self.restarted_once = False

    def tick(self) -> None:
        with self.lock:
            self.line_current = next_line_current(self.breaker_closed)

    def in_outage(self) -> bool:
        return time.time() < self.restart_until

    def handle_select(self, control_code: int) -> int:
        with self.lock:
            self.pending_select = (control_code, time.time())
        return CONTROL_SUCCESS

    def handle_operate(self, control_code: int) -> int:
        with self.lock:
            if self.pending_select is None:
                return CONTROL_NO_SELECT
            sel_code, sel_time = self.pending_select
            self.pending_select = None
            if sel_code != control_code or (time.time() - sel_time) > SELECT_VALIDITY_SECONDS:
                return CONTROL_NO_SELECT
            self.breaker_closed = control_code == CROB_CLOSE
            return CONTROL_SUCCESS

    def handle_direct_operate(self, control_code: int) -> int:
        with self.lock:
            self.breaker_closed = control_code == CROB_CLOSE
        return CONTROL_SUCCESS

    def handle_cold_restart(self) -> None:
        with self.lock:
            self.restart_until = time.time() + REBOOT_SECONDS
            self.restarted_once = True
        log.info("COLD_RESTART received — going silent for %.0fs (simulated reboot)", REBOOT_SECONDS)

    def status_objects_and_iin(self) -> tuple[bytes, int]:
        with self.lock:
            objs = encode_full_status(self.breaker_closed, self.line_current)
            iin1 = IIN1_DEVICE_RESTART if self.restarted_once else 0
        return objs, iin1


def _handle_client(conn: socket.socket, addr, station: Outstation) -> None:
    log.info("master connected from %s", addr)
    try:
        while True:
            try:
                control, dest, src, user_data = recv_frame(conn)
            except ConnectionError:
                break

            if station.in_outage():
                log.info("in simulated outage — dropping request silently")
                continue

            app = unwrap_transport(user_data)
            function_code, off = parse_app_header(app)
            seq = app[0] & 0x0F

            if function_code == FC_READ:
                objs, iin1 = station.status_objects_and_iin()
                resp = build_app_response(seq, iin1, 0, objs)

            elif function_code in (FC_SELECT, FC_OPERATE, FC_DIRECT_OPERATE):
                control_code, _status = decode_crob(app[off:])
                if function_code == FC_SELECT:
                    result = station.handle_select(control_code)
                elif function_code == FC_OPERATE:
                    result = station.handle_operate(control_code)
                else:
                    result = station.handle_direct_operate(control_code)

                objs, iin1 = encode_crob(control_code, status=result), 0
                resp = build_app_response(seq, iin1, 0, objs)
                action = {FC_SELECT: "SELECT", FC_OPERATE: "OPERATE", FC_DIRECT_OPERATE: "DIRECT_OPERATE"}[
                    function_code
                ]
                log.info(
                    "%s control_code=%#x result=%s breaker_closed=%s",
                    action,
                    control_code,
                    "SUCCESS" if result == CONTROL_SUCCESS else "NO_SELECT",
                    station.breaker_closed,
                )

            elif function_code == FC_COLD_RESTART:
                station.handle_cold_restart()
                resp = build_app_response(seq, 0, 0, encode_time_delay(int(REBOOT_SECONDS)))

            else:
                continue

            frame = wrap_frame(0x44, dest=src, src=dest, user_data=wrap_transport(resp, seq))
            conn.sendall(frame)
    finally:
        conn.close()
        log.info("master disconnected from %s", addr)


def _tick_loop(station: Outstation, tick_seconds: float) -> None:
    while True:
        time.sleep(tick_seconds)
        station.tick()
        log.info(
            "breaker_closed=%s line_current=%.1fA in_outage=%s",
            station.breaker_closed,
            station.line_current,
            station.in_outage(),
        )


def run(host: str, port: int, tick_seconds: float) -> None:
    station = Outstation()
    threading.Thread(target=_tick_loop, args=(station, tick_seconds), daemon=True).start()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    log.info("DNP3 outstation listening on %s:%d", host, port)
    try:
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=_handle_client, args=(conn, addr, station), daemon=True).start()
    finally:
        server_sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="DNP3 substation breaker simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=20000)
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
