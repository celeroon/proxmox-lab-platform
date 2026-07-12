"""Modbus/TCP server simulating a tank + pump field device.

Standalone run (production / systemd):
    python3 modbus_server.py --host 0.0.0.0 --port 502

Importable pieces (build_context, tick) are reused directly by the local
round-trip test in tests/test_modbus_roundtrip.py — no duplicated logic.
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import ServerAsyncStop, StartAsyncTcpServer

from modbus_logic import (
    COIL_PUMP_RUN,
    DEFAULT_ALARM_THRESHOLD,
    DISCRETE_HIGH_ALARM,
    HOLDING_ALARM_THRESHOLD,
    HOLDING_LEVEL,
    is_high_alarm,
    level_to_register,
    register_to_level,
    update_level,
)

log = logging.getLogger("modbus_server")

# Function codes used purely as block selectors for getValues/setValues —
# pymodbus routes fc -> block ("d"=di, "c"=co, "h"=hr, "i"=ir) via decode().
# Using READ_DISCRETE_INPUTS (2) to *write* the di block from our own tick
# loop is the documented pymodbus idiom (see its bundled "updating_server"
# example) for a server-internal value no real client can write over the wire.
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
WRITE_SINGLE_REGISTER = 6


def build_context(
    initial_level: float = 10.0, alarm_threshold: float = DEFAULT_ALARM_THRESHOLD
) -> ModbusServerContext:
    slave = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [False] * 10),
        co=ModbusSequentialDataBlock(0, [False] * 10),
        hr=ModbusSequentialDataBlock(0, [0] * 10),
        ir=ModbusSequentialDataBlock(0, [0] * 10),
        zero_mode=True,  # logical address N == block index N, no off-by-one
    )
    slave.setValues(WRITE_SINGLE_REGISTER, HOLDING_LEVEL, [level_to_register(initial_level)])
    slave.setValues(
        WRITE_SINGLE_REGISTER, HOLDING_ALARM_THRESHOLD, [level_to_register(alarm_threshold)]
    )
    return ModbusServerContext(slaves=slave, single=True)


def build_identity() -> ModbusDeviceIdentification:
    """Without this, FC 43 (Read Device Identification) requests still get a valid
    response, but with zero objects — pymodbus doesn't populate any vendor/product
    info unless explicitly given an identity, so Malcolm's "Device Identification
    Objects" panel stays empty even though the request/response round-trip works.
    """
    return ModbusDeviceIdentification(
        info_name={
            "VendorName": "OT-Lab",
            "ProductCode": "TANK-SIM",
            "VendorUrl": "https://example.invalid/ot-lab",
            "ProductName": "Tank+Pump Simulator",
            "ModelName": "TankSim-1",
            "MajorMinorRevision": "1.0",
        }
    )


def tick(context: ModbusServerContext, dt: float) -> float:
    """Advance the simulated tank by one step. Returns the new level (%)."""
    slave = context[0]
    pump_on = bool(slave.getValues(READ_COILS, COIL_PUMP_RUN, count=1)[0])
    level = register_to_level(slave.getValues(READ_HOLDING_REGISTERS, HOLDING_LEVEL, count=1)[0])
    threshold = register_to_level(
        slave.getValues(READ_HOLDING_REGISTERS, HOLDING_ALARM_THRESHOLD, count=1)[0]
    )

    new_level = update_level(level, pump_on, dt)
    slave.setValues(WRITE_SINGLE_REGISTER, HOLDING_LEVEL, [level_to_register(new_level)])
    slave.setValues(
        READ_DISCRETE_INPUTS, DISCRETE_HIGH_ALARM, [is_high_alarm(new_level, threshold)]
    )
    return new_level


async def simulate_tank(context: ModbusServerContext, tick_seconds: float) -> None:
    while True:
        await asyncio.sleep(tick_seconds)
        level = tick(context, tick_seconds)
        slave = context[0]
        pump_on = bool(slave.getValues(READ_COILS, COIL_PUMP_RUN, count=1)[0])
        high_alarm = bool(slave.getValues(READ_DISCRETE_INPUTS, DISCRETE_HIGH_ALARM, count=1)[0])
        threshold = register_to_level(
            slave.getValues(READ_HOLDING_REGISTERS, HOLDING_ALARM_THRESHOLD, count=1)[0]
        )
        log.info(
            "tank level=%.1f%% pump_on=%s high_alarm=%s threshold=%.1f%%",
            level, pump_on, high_alarm, threshold,
        )


async def run(host: str, port: int, tick_seconds: float) -> None:
    context = build_context()
    identity = build_identity()
    sim_task = asyncio.create_task(simulate_tank(context, tick_seconds))
    try:
        await StartAsyncTcpServer(context=context, identity=identity, address=(host, port))
    finally:
        sim_task.cancel()


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus tank+pump field device simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--tick-seconds", type=float, default=1.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    asyncio.run(run(args.host, args.port, args.tick_seconds))


if __name__ == "__main__":
    main()
