"""EtherNet/IP-CIP client simulating an HMI mirroring the sensor onto the solenoid.

Standalone run (production / systemd):
    python3 enip_client.py --host 10.2.0.13 --port 44818

Writing a BOOL tag in cpppo needs an explicit type cast in the tag string —
bare "Solenoid1=1" is silently rejected (CIP status 255, a type mismatch
against the INT cpppo infers from a bare numeral); confirmed by direct
testing. "Solenoid1=(BOOL)1" is the correct syntax — see write_solenoid().

poll_once() is reused directly by the local round-trip test.
"""

from __future__ import annotations

import argparse
import logging
import random
import time
from dataclasses import dataclass

from cpppo.server.enip import client

from enip_logic import TAG_SENSOR, TAG_SOLENOID, desired_solenoid_state

log = logging.getLogger("enip_client")

EXTERNAL_PROBE_MIN_DELAY = 60   # 1-5 minutes, matching modbus/s7comm/bacnet's external probe
EXTERNAL_PROBE_MAX_DELAY = 300


@dataclass
class RackReading:
    sensor_active: bool
    solenoid_on: bool


def read_sensor(conn: client.connector) -> bool:
    ops = client.parse_operations([TAG_SENSOR])
    failures, transactions = conn.process(operations=ops, depth=1, multiple=0, fragment=False, printing=False)
    if failures:
        raise RuntimeError(f"read {TAG_SENSOR} failed")
    return bool(transactions[0][0])


def write_solenoid(conn: client.connector, on: bool) -> bool:
    ops = client.parse_operations([f"{TAG_SOLENOID}=(BOOL){1 if on else 0}"])
    failures, _transactions = conn.process(operations=ops, depth=1, multiple=0, fragment=False, printing=False)
    return failures == 0


def poll_once(conn: client.connector) -> RackReading:
    sensor_active = read_sensor(conn)
    desired = desired_solenoid_state(sensor_active)
    write_solenoid(conn, desired)
    return RackReading(sensor_active=sensor_active, solenoid_on=desired)


def external_probe(ip: str, port: int) -> None:
    """Perform a real EtherNet/IP-CIP tag read against ip:port to generate
    external-destination ICS traffic for Malcolm's 'ICS/IoT External Traffic'
    panel. Same rationale as modbus/s7comm/bacnet's external_probe -- a bare
    connect never gets tagged `ics`/`ics_best_guess`, only a genuine protocol
    exchange does. `ip` is expected to be a VyOS loopback (9.9.9.9) with a
    hairpin DNAT redirecting this exact flow back to the real enip-server, so
    this read genuinely succeeds while Zeek's mirror still sees the pre-NAT
    external destination. Uses its own short-lived connector, never the main
    polling connection, matching s7comm's precedent (mixing message types on
    one persistent connection risked desyncing Malcolm's parser there).
    """
    try:
        with client.connector(host=ip, port=port, timeout=5.0) as conn:
            read_sensor(conn)
    except Exception:
        pass  # connection/read failure is fine -- the exchange attempt is what Malcolm needs


def run(
    host: str,
    port: int,
    poll_seconds: float,
    external_probe_ip: str | None = None,
    external_probe_port: int = 44818,
) -> None:
    with client.connector(host=host, port=port, timeout=5.0) as conn:
        next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)
        while True:
            reading = poll_once(conn)
            log.info("sensor_active=%s solenoid_on=%s", reading.sensor_active, reading.solenoid_on)

            if external_probe_ip and time.time() >= next_probe_time:
                external_probe(external_probe_ip, external_probe_port)
                next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)

            time.sleep(poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="EtherNet/IP-CIP HMI simulator")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=44818)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    parser.add_argument(
        "--external-probe-ip",
        default=None,
        help="IP to probe every 1-5 min to generate 'external' traffic visible in Malcolm",
    )
    parser.add_argument("--external-probe-port", type=int, default=44818)
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    for noisy in ("cpppo", "enip", "network"):  # cpppo dumps full CIP packet traces at INFO
        logging.getLogger(noisy).setLevel(logging.WARNING)
    run(
        args.host,
        args.port,
        args.poll_seconds,
        external_probe_ip=args.external_probe_ip,
        external_probe_port=args.external_probe_port,
    )


if __name__ == "__main__":
    main()
