"""S7comm server simulating a conveyor-belt PLC (DB1: motor_running, item_count).

Standalone run (production / systemd):
    python3 s7_server.py --host 0.0.0.0 --port 102

build_db()/tick() are reused directly by the local round-trip test.

snap7's Server.start() spawns its own background thread and returns immediately
— there is no async API here at all, so this script is plain synchronous code,
not asyncio (unlike the Modbus scripts, where pymodbus is async-native).

Note: PLC_STOP/PLC_HOT_START genuinely flip this server's real internal
server.cpu_state via the actual S7comm protocol handling (snap7's pure-Python
server implementation) — this isn't simulated by us, it's the real protocol.
client.get_cpu_state() is unreliable in snap7 3.0.0 (always reports "Run"
regardless of actual state, confirmed by direct testing) — so we read
server.cpu_state server-side instead, and the client infers PLC state from
whether item_count is still advancing, not from asking the PLC directly.
"""

from __future__ import annotations

import argparse
import logging
import time

import snap7
import snap7.util as util
from snap7.server import CPUState
from snap7.type import SrvArea

from s7_logic import (
    DB_NUMBER,
    DB_SIZE,
    ITEM_COUNT_BYTE,
    MOTOR_RUNNING_BIT,
    MOTOR_RUNNING_BYTE,
    next_item_count,
)

log = logging.getLogger("s7_server")


def build_db(motor_running: bool = True) -> bytearray:
    db = bytearray(DB_SIZE)
    util.set_bool(db, MOTOR_RUNNING_BYTE, MOTOR_RUNNING_BIT, motor_running)
    util.set_dint(db, ITEM_COUNT_BYTE, 0)
    return db


def tick(db: bytearray, cpu_state: int) -> int:
    """Advance the conveyor by one step in place. Returns the new item_count."""
    motor_running = util.get_bool(db, MOTOR_RUNNING_BYTE, MOTOR_RUNNING_BIT)
    item_count = util.get_dint(db, ITEM_COUNT_BYTE)
    new_count = next_item_count(item_count, motor_running, cpu_state == CPUState.RUN)
    util.set_dint(db, ITEM_COUNT_BYTE, new_count)
    return new_count


def run(host: str, port: int, tick_seconds: float) -> None:
    server = snap7.Server()
    db = build_db()
    server.register_area(SrvArea.DB, DB_NUMBER, db)
    server.start(tcp_port=port)
    log.info("S7comm server listening on %s:%d (DB%d)", host, port, DB_NUMBER)
    try:
        while True:
            time.sleep(tick_seconds)
            count = tick(db, server.cpu_state)
            log.info(
                "item_count=%d motor_running=%s cpu_state=%s",
                count,
                util.get_bool(db, MOTOR_RUNNING_BYTE, MOTOR_RUNNING_BIT),
                server.cpu_state.name,
            )
    finally:
        server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="S7comm conveyor PLC simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=102)
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
