"""OPC-UA server simulating a generic machine on a SCADA historian
(Speed/Status/FaultCode under a Machine1 object).

Standalone run (production / systemd):
    python3 opcua_server.py --host 0.0.0.0 --port 4840

No autonomous control loop here, unlike BACnet's RTU — Status is purely a
command the client/attacker sets; the server's background tick just runs the
Speed physics consistent with whatever Status currently says.

asyncua is fully asyncio-native and well-behaved — confirmed by direct
testing: read/write/subscribe all work exactly as documented, no gotchas like
pymodbus's API churn, snap7's get_cpu_state bug, cpppo's BOOL cast
requirement, or BAC0's 0.0.0.0/write() issues.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import random

from asyncua import Server

from opcua_logic import (
    NAMESPACE_URI,
    OBJECT_NAME,
    STATUS_RUNNING,
    TAG_FAULT_CODE,
    TAG_SPEED,
    TAG_STATUS,
    next_speed,
)

log = logging.getLogger("opcua_server")


async def build_machine(server: Server):
    idx = await server.register_namespace(NAMESPACE_URI)
    machine = await server.nodes.objects.add_object(idx, OBJECT_NAME)
    speed = await machine.add_variable(idx, TAG_SPEED, 0.0)
    status = await machine.add_variable(idx, TAG_STATUS, "Stopped")
    fault_code = await machine.add_variable(idx, TAG_FAULT_CODE, 0)
    await speed.set_writable()
    await status.set_writable()
    await fault_code.set_writable()
    return speed, status, fault_code


async def tick(speed_node, status_node) -> float:
    speed = await speed_node.get_value()
    status = await status_node.get_value()
    new_speed = next_speed(speed, running=status == STATUS_RUNNING, jitter=random.uniform(-15.0, 15.0))
    await speed_node.write_value(float(new_speed))
    return new_speed


async def run(host: str, port: int, tick_seconds: float) -> None:
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://{host}:{port}/ics-sim/server/")
    speed_node, status_node, fault_node = await build_machine(server)

    async with server:
        log.info("OPC-UA server listening on opc.tcp://%s:%d/ics-sim/server/", host, port)
        while True:
            await asyncio.sleep(tick_seconds)
            new_speed = await tick(speed_node, status_node)
            status = await status_node.get_value()
            fault = await fault_node.get_value()
            log.info("Speed=%.1f Status=%s FaultCode=%d", new_speed, status, fault)


def main() -> None:
    parser = argparse.ArgumentParser(description="OPC-UA generic machine simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4840)
    parser.add_argument("--tick-seconds", type=float, default=1.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    logging.getLogger("asyncua").setLevel(logging.WARNING)
    asyncio.run(run(args.host, args.port, args.tick_seconds))


if __name__ == "__main__":
    main()
