"""BACnet server simulating an HVAC zone RTU controller (Temperature,
Setpoint, UnitRunning).

Standalone run (production / systemd):
    python3 bacnet_server.py --host 0.0.0.0 --port 47808

BAC0 (built on bacpypes3) is fully asyncio-native — BAC0.lite() looks like a
plain function but actually needs a running event loop (confirmed by direct
testing: calling it outside one raises "no running event loop"). The
thermostat's hysteresis loop runs autonomously here, server-side, same as a
real local RTU — direct attribute assignment on the bacpypes3 object
(obj.presentValue = ...) is used instead of BAC0's own write() convenience
method, since that one is fire-and-forget (a background DoOnce task with no
returned confirmation) and isn't needed for the server's own local state
anyway.
"""

from __future__ import annotations

import argparse
import asyncio
import logging

import BAC0
from BAC0.core.devices.local.factory import analog_value, binary_value, temperature_value
from bacpypes3.basetypes import BinaryPV
from bacpypes3.primitivedata import Real

from bacnet_logic import (
    SETPOINT_INSTANCE,
    TAG_SETPOINT,
    TAG_TEMPERATURE,
    TAG_UNIT_RUNNING,
    TEMPERATURE_INSTANCE,
    UNIT_RUNNING_INSTANCE,
    desired_unit_running,
    next_temperature,
)

log = logging.getLogger("bacnet_server")


def build_objects(instance, initial_temp: float, initial_setpoint: float):
    temp = temperature_value(name=TAG_TEMPERATURE, presentValue=initial_temp, instance=TEMPERATURE_INSTANCE)
    temp.add_objects_to_application(instance)
    setpt = analog_value(
        name=TAG_SETPOINT, presentValue=initial_setpoint, instance=SETPOINT_INSTANCE, is_commandable=True
    )
    setpt.add_objects_to_application(instance)
    running = binary_value(
        name=TAG_UNIT_RUNNING, presentValue="inactive", instance=UNIT_RUNNING_INSTANCE, is_commandable=True
    )
    running.add_objects_to_application(instance)

    app = instance.this_application.app
    by_name = {o.objectName: o for o in app.iter_objects()}
    return by_name[TAG_TEMPERATURE], by_name[TAG_SETPOINT], by_name[TAG_UNIT_RUNNING]


async def tick(temp_obj, setpt_obj, running_obj) -> None:
    temp = float(temp_obj.presentValue)
    setpoint = float(setpt_obj.presentValue)
    currently_running = str(running_obj.presentValue) == "active"

    running_now = desired_unit_running(temp, setpoint, currently_running)
    new_temp = next_temperature(temp, running_now)

    running_obj.presentValue = BinaryPV("active" if running_now else "inactive")
    temp_obj.presentValue = Real(new_temp)
    log.info("Temperature=%.1f Setpoint=%.1f UnitRunning=%s", new_temp, setpoint, running_now)


async def run(host: str, port: int, tick_seconds: float) -> None:
    instance = BAC0.lite(ip=host, port=port)
    await asyncio.sleep(0.5)
    temp_obj, setpt_obj, running_obj = build_objects(instance, initial_temp=20.0, initial_setpoint=22.0)
    log.info("BACnet server listening on %s:%d (Temperature, Setpoint, UnitRunning)", host, port)
    try:
        while True:
            await asyncio.sleep(tick_seconds)
            await tick(temp_obj, setpt_obj, running_obj)
    finally:
        instance.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="BACnet HVAC zone simulator")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="a concrete local IP, never 0.0.0.0 — bacpypes3 computes its broadcast "
        "address from this and fails to bind with the wildcard address (confirmed by "
        "direct testing: 'Cannot assign requested address'). On a real VM, pass its "
        "actual management IP.",
    )
    parser.add_argument("--port", type=int, default=47808)
    parser.add_argument("--tick-seconds", type=float, default=1.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    for noisy in ("BAC0_Root", "bacpypes3"):  # BAC0's actual top-level logger is "BAC0_Root", not "BAC0"
        logging.getLogger(noisy).setLevel(logging.WARNING)
    asyncio.run(run(args.host, args.port, args.tick_seconds))


if __name__ == "__main__":
    main()
