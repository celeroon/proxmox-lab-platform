"""S7comm client simulating an engineering workstation monitoring the conveyor.

Standalone run (production / systemd):
    python3 s7_client.py --host 10.2.0.11 --port 102

Deliberately does NOT call get_cpu_state() — confirmed via direct testing that
snap7 3.0.0's client always reports "Run" regardless of the server's actual
state (a library bug, not a simulation choice). Instead this infers "is the
PLC actually executing" the same way a real operator would notice: production
(item_count) has stopped advancing, even though nothing else looks wrong.

poll_once() is reused directly by the local round-trip test. Plain synchronous
code — snap7 has no async API at all.
"""

from __future__ import annotations

import argparse
import logging
import random
import time
from dataclasses import dataclass

import snap7
import snap7.util as util

from s7_logic import DB_NUMBER, ITEM_COUNT_BYTE, MOTOR_RUNNING_BIT, MOTOR_RUNNING_BYTE

log = logging.getLogger("s7_client")

READ_SIZE = 6  # covers byte 0 (motor_running) + byte 1 (gap) + bytes 2-5 (item_count)
TOGGLE_EVERY_N_POLLS = 10  # routine operator on/off cycling, distinct from a PLC-level stop
EXTERNAL_PROBE_MIN_DELAY = 60   # 1-5 minutes, matching modbus_client.py's external probe
EXTERNAL_PROBE_MAX_DELAY = 300


@dataclass
class ConveyorReading:
    item_count: int
    motor_running: bool
    producing: bool  # item_count actually advanced since the last poll


def poll_once(client: snap7.Client, previous_count: int | None) -> ConveyorReading:
    buf = client.db_read(DB_NUMBER, 0, READ_SIZE)
    item_count = util.get_dint(buf, ITEM_COUNT_BYTE)
    motor_running = util.get_bool(buf, MOTOR_RUNNING_BYTE, MOTOR_RUNNING_BIT)
    producing = previous_count is not None and item_count > previous_count
    return ConveyorReading(item_count=item_count, motor_running=motor_running, producing=producing)


def toggle_motor(client: snap7.Client, motor_running: bool) -> None:
    buf = client.db_read(DB_NUMBER, 0, READ_SIZE)
    util.set_bool(buf, MOTOR_RUNNING_BYTE, MOTOR_RUNNING_BIT, not motor_running)
    client.db_write(DB_NUMBER, 0, buf)


def external_probe(ip: str, port: int) -> None:
    """Perform a real S7comm read against ip:port to generate external-destination
    ICS traffic visible to Malcolm's 'ICS/IoT External Traffic' dashboard panel.

    Same rationale as modbus_client.py's external_probe_loop: a bare TCP
    connect+close never gets tagged `ics`/`ics_best_guess` — only a genuine
    protocol exchange does. `ip` is expected to be a VyOS loopback (9.9.9.9)
    with a hairpin DNAT redirecting this exact flow back to the real
    s7comm-server (see vyos/configure_external_traffic_redirect), so this read
    genuinely succeeds against real DB1 data while Zeek's mirror still sees
    the pre-NAT external destination. Uses a separate short-lived connection,
    not the main polling connection — confirmed live 2026-07-04 that mixing
    unrelated message types on one connection can desync Malcolm's S7comm
    Zeek parser for the rest of that connection, so this stays isolated the
    same way s7comm_attack.py's techniques do.
    """
    probe_client = snap7.Client()
    try:
        probe_client.connect(ip, 0, 1, tcp_port=port)
        probe_client.db_read(DB_NUMBER, 0, READ_SIZE)
    except Exception:
        pass  # connection/read failure is fine — the exchange attempt is what Malcolm needs
    finally:
        probe_client.disconnect()


def run(
    host: str,
    port: int,
    poll_seconds: float,
    external_probe_ip: str | None = None,
    external_probe_port: int = 102,
) -> None:
    client = snap7.Client()
    client.connect(host, 0, 1, tcp_port=port)
    next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)
    try:
        previous_count: int | None = None
        poll_index = 0
        while True:
            reading = poll_once(client, previous_count)
            log.info(
                "item_count=%d motor_running=%s producing=%s",
                reading.item_count,
                reading.motor_running,
                reading.producing,
            )
            if poll_index > 0 and poll_index % TOGGLE_EVERY_N_POLLS == 0:
                toggle_motor(client, reading.motor_running)
                log.info("routine operator toggle: motor_running -> %s", not reading.motor_running)
            if external_probe_ip and time.time() >= next_probe_time:
                external_probe(external_probe_ip, external_probe_port)
                next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)
            previous_count = reading.item_count
            poll_index += 1
            time.sleep(poll_seconds)
    finally:
        client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="S7comm engineering workstation simulator")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    parser.add_argument(
        "--external-probe-ip",
        default=None,
        help="IP to probe every 1-5 min to generate 'external' traffic visible in Malcolm",
    )
    parser.add_argument("--external-probe-port", type=int, default=102)
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
