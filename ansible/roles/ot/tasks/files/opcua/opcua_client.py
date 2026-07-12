"""OPC-UA client simulating a SCADA historian watching the machine.

Standalone run (production / systemd):
    python3 opcua_client.py --host 192.168.60.10 --port 4840

The one protocol here where the client genuinely behaves differently:
SUBSCRIBES to Speed/Status changes (push, server notifies on change) instead
of polling on a timer like every other protocol's client. Confirmed by direct
testing: subscribing delivers an immediate notification with the current
value, then a fresh one on every actual change — no polling loop needed for
monitoring at all. A separate timer still drives the occasional start/stop
command, since that's this client's own decision, not something to subscribe to.

find_nodes()/toggle_status() are reused directly by the local round-trip test.

ChangeLogger's tag-name mapping and external_probe()/--external-probe-ip are
both additions here: a naive datachange_notification() logs the raw asyncua
Node object (unhelpful for a log-tailing TUI, since it doesn't stringify to
"Speed"/"Status"), and the base design has no "ICS/IoT External Traffic" demo
like every other protocol pair here.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import random
import time

from asyncua import Client

from opcua_logic import NAMESPACE_URI, OBJECT_NAME, STATUS_RUNNING, STATUS_STOPPED, TAG_STATUS, TAG_SPEED

log = logging.getLogger("opcua_client")

TOGGLE_EVERY_SECONDS = 20.0
EXTERNAL_PROBE_MIN_DELAY = 60  # 1-5 minutes, matching every other protocol's external probe
EXTERNAL_PROBE_MAX_DELAY = 300


class ChangeLogger:
    def __init__(self, names: dict) -> None:
        self._names = names  # {node: tag_name} -- see module docstring

    def datachange_notification(self, node, val, data) -> None:
        name = self._names.get(node, str(node))
        log.info("push update: %s -> %s", name, val)


async def find_nodes(client: Client):
    idx = await client.get_namespace_index(NAMESPACE_URI)
    objects = client.get_objects_node()
    machine = await objects.get_child([f"{idx}:{OBJECT_NAME}"])
    speed = await machine.get_child([f"{idx}:{TAG_SPEED}"])
    status = await machine.get_child([f"{idx}:{TAG_STATUS}"])
    return speed, status


async def toggle_status(status_node) -> str:
    current = await status_node.get_value()
    new_status = STATUS_STOPPED if current == STATUS_RUNNING else STATUS_RUNNING
    await status_node.write_value(new_status)
    return new_status


async def _toggle_loop(status_node, toggle_seconds: float) -> None:
    while True:
        await asyncio.sleep(toggle_seconds)
        new_status = await toggle_status(status_node)
        log.info("routine operator command -> %s", new_status)


async def external_probe(ip: str, port: int) -> None:
    """Perform a real OPC-UA read against ip:port on its own short-lived
    connection to generate external-destination ICS traffic. See module
    docstring and every other protocol pair's external_probe() here."""
    try:
        async with Client(url=f"opc.tcp://{ip}:{port}/ics-sim/server/") as probe_client:
            speed_node, _status_node = await find_nodes(probe_client)
            await speed_node.get_value()
    except Exception:
        pass  # connection/read failure is fine -- the exchange attempt is what Malcolm needs


async def _external_probe_loop(ip: str, port: int) -> None:
    next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)
    while True:
        await asyncio.sleep(1.0)
        if time.time() >= next_probe_time:
            await external_probe(ip, port)
            next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)


async def run(host: str, port: int, toggle_seconds: float, external_probe_ip: str | None = None, external_probe_port: int = 4840) -> None:
    async with Client(url=f"opc.tcp://{host}:{port}/ics-sim/server/") as client:
        speed_node, status_node = await find_nodes(client)

        handler = ChangeLogger({speed_node: "Speed", status_node: "Status"})
        sub = await client.create_subscription(500, handler)
        await sub.subscribe_data_change([speed_node, status_node])

        tasks = [_toggle_loop(status_node, toggle_seconds)]
        if external_probe_ip:
            tasks.append(_external_probe_loop(external_probe_ip, external_probe_port))
        await asyncio.gather(*tasks)


def main() -> None:
    parser = argparse.ArgumentParser(description="OPC-UA SCADA historian simulator")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=4840)
    parser.add_argument("--toggle-seconds", type=float, default=TOGGLE_EVERY_SECONDS)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    parser.add_argument(
        "--external-probe-ip",
        default=None,
        help="IP to probe every 1-5 min to generate 'external' traffic visible in Malcolm",
    )
    parser.add_argument("--external-probe-port", type=int, default=4840)
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    logging.getLogger("asyncua").setLevel(logging.WARNING)
    asyncio.run(
        run(
            args.host,
            args.port,
            args.toggle_seconds,
            external_probe_ip=args.external_probe_ip,
            external_probe_port=args.external_probe_port,
        )
    )


if __name__ == "__main__":
    main()
