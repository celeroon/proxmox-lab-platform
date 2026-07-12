"""DNP3 master simulating a SCADA control room monitoring/operating the breaker.

Standalone run (production / systemd):
    python3 dnp3_client.py --host 192.168.30.10 --port 20000

Uses the safer two-step SELECT-then-OPERATE pattern for control, the way a
real master is supposed to (vs. the attacker's one-step DIRECT_OPERATE).
A socket timeout is set deliberately — during the server's simulated reboot
outage, requests get no response at all, and a real master would see exactly
this: a timeout, not an error.

poll_once()/toggle_breaker() are reused directly by the local round-trip test.

external_probe()/--external-probe-ip is added to match every other protocol pair in
this lab (modbus_client.py/s7_client.py/bacnet_client.py/enip_client.py) —
periodic genuine protocol traffic to a VyOS loopback (9.9.9.9), hairpinned
back to this same dnp3-server, so Malcolm's "ICS/IoT External Traffic" panel
has something real to show. A bare TCP connect+close never gets tagged
`ics`/`ics_best_guess` — only an actual protocol exchange does. Runs over its
own short-lived connection, not the main polling connection, so a probe
failure can never affect the routine poll loop.
"""

from __future__ import annotations

import argparse
import logging
import random
import socket
import time
from dataclasses import dataclass

from dnp3_logic import CROB_CLOSE, CROB_TRIP, IIN1_DEVICE_RESTART, MASTER_CONTROL
from dnp3_protocol import (
    FC_OPERATE,
    FC_READ,
    FC_SELECT,
    build_app_request,
    decode_crob,
    decode_full_status,
    encode_class_read,
    encode_crob,
    parse_app_header,
    parse_response_header,
    recv_frame,
    unwrap_transport,
    wrap_frame,
    wrap_transport,
)

log = logging.getLogger("dnp3_client")

MASTER_ADDR = 2
OUTSTATION_ADDR = 1
TOGGLE_EVERY_N_POLLS = 8
EXTERNAL_PROBE_MIN_DELAY = 60  # 1-5 minutes, matching modbus_client.py/s7_client.py's external probe
EXTERNAL_PROBE_MAX_DELAY = 300


@dataclass
class BreakerReading:
    breaker_closed: bool
    line_current: float
    device_restart: bool


def _send_request(sock: socket.socket, function_code: int, seq: int, object_bytes: bytes = b"") -> None:
    req = build_app_request(function_code, seq, object_bytes)
    frame = wrap_frame(MASTER_CONTROL, dest=OUTSTATION_ADDR, src=MASTER_ADDR, user_data=wrap_transport(req, seq))
    sock.sendall(frame)


def poll_once(sock: socket.socket, seq: int) -> BreakerReading:
    _send_request(sock, FC_READ, seq, encode_class_read(0))
    _control, _dest, _src, user_data = recv_frame(sock)
    iin1, _iin2, obj_bytes = parse_response_header(unwrap_transport(user_data))
    closed, current = decode_full_status(obj_bytes)
    return BreakerReading(
        breaker_closed=closed, line_current=current, device_restart=bool(iin1 & IIN1_DEVICE_RESTART)
    )


def toggle_breaker(sock: socket.socket, currently_closed: bool, seq: int) -> bool:
    """SELECT then OPERATE — the safer two-step pattern. Returns True on success."""
    control_code = CROB_TRIP if currently_closed else CROB_CLOSE

    _send_request(sock, FC_SELECT, seq, encode_crob(control_code))
    _control, _dest, _src, user_data = recv_frame(sock)
    app = unwrap_transport(user_data)
    _fc, off = parse_app_header(app)
    _code, select_status = decode_crob(app[off:])
    if select_status != 0:
        return False

    _send_request(sock, FC_OPERATE, seq + 1, encode_crob(control_code))
    _control, _dest, _src, user_data2 = recv_frame(sock)
    app2 = unwrap_transport(user_data2)
    _fc2, off2 = parse_app_header(app2)
    _code2, operate_status = decode_crob(app2[off2:])
    return operate_status == 0


def external_probe(ip: str, port: int) -> None:
    """Perform a real DNP3 READ against ip:port on its own short-lived connection
    to generate external-destination ICS traffic. See module docstring."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((ip, port))
        poll_once(sock, seq=0)
    except Exception:
        pass  # connection/read failure is fine — the exchange attempt is what Malcolm needs
    finally:
        sock.close()


def run(host: str, port: int, poll_seconds: float, external_probe_ip: str | None = None, external_probe_port: int = 20000) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)
    try:
        seq = 0
        poll_index = 0
        while True:
            try:
                reading = poll_once(sock, seq)
                log.info(
                    "breaker_closed=%s line_current=%.1fA device_restart=%s",
                    reading.breaker_closed,
                    reading.line_current,
                    reading.device_restart,
                )
                seq += 1

                if poll_index > 0 and poll_index % TOGGLE_EVERY_N_POLLS == 0:
                    ok = toggle_breaker(sock, reading.breaker_closed, seq)
                    seq += 2
                    log.info("routine SELECT+OPERATE toggle -> success=%s", ok)
            except socket.timeout:
                log.info("no response (timeout) — outstation may be restarting")

            if external_probe_ip and time.time() >= next_probe_time:
                external_probe(external_probe_ip, external_probe_port)
                next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)

            poll_index += 1
            time.sleep(poll_seconds)
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="DNP3 SCADA master simulator")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    parser.add_argument(
        "--external-probe-ip",
        default=None,
        help="IP to probe every 1-5 min to generate 'external' traffic visible in Malcolm",
    )
    parser.add_argument("--external-probe-port", type=int, default=20000)
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
