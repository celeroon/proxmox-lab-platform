"""EtherNet/IP-CIP server simulating a sensor+solenoid I/O rack.

Standalone run (production / systemd):
    python3 enip_server.py --host 0.0.0.0 --port 44818

cpppo has no async/threaded "start the server, get an object back" API like
pymodbus — main() runs the whole reactor loop itself (blocking), and the only
hook for background work is idle_service, called roughly every 0.1s regardless
of what you do in it. Throttled here to tick_seconds using a plain timestamp
check, same idea as the other protocols' background ticks, just driven by a
callback instead of an asyncio task or a separate thread.

Tag values are read/written through the module-level `tags` dotdict cpppo
populates at startup — `tags['Sensor1.attribute'][0]` is the live value, not a
copy, so writing it here is immediately visible to any connected client.
"""

from __future__ import annotations

import argparse
import logging
import time

from cpppo.server.enip.main import main as enip_main
from cpppo.server.enip.main import tags

from enip_logic import TAG_SENSOR, TAG_SOLENOID, should_toggle_sensor

log = logging.getLogger("enip_server")


def make_idle_service(tick_seconds: float):
    state = {"last_tick": 0.0, "tick_count": 0, "sensor": False}

    def idle() -> None:
        now = time.time()
        if now - state["last_tick"] < tick_seconds:
            return
        state["last_tick"] = now
        state["tick_count"] += 1
        if should_toggle_sensor(state["tick_count"]):
            state["sensor"] = not state["sensor"]
            tags[f"{TAG_SENSOR}.attribute"][0] = 1 if state["sensor"] else 0
            log.info(
                "Sensor1=%s Solenoid1=%s",
                bool(tags[f"{TAG_SENSOR}.attribute"][0]),
                bool(tags[f"{TAG_SOLENOID}.attribute"][0]),
            )

    return idle


def run(host: str, port: int, tick_seconds: float) -> None:
    log.info("EtherNet/IP-CIP server listening on %s:%d (Sensor1, Solenoid1)", host, port)
    enip_main(
        argv=["--address", f"{host}:{port}", f"{TAG_SENSOR}=BOOL", f"{TAG_SOLENOID}=BOOL"],
        idle_service=make_idle_service(tick_seconds),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="EtherNet/IP-CIP sensor+solenoid rack simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=44818)
    parser.add_argument("--tick-seconds", type=float, default=1.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    for noisy in ("cpppo", "enip", "network"):  # cpppo dumps full CIP packet traces at INFO
        logging.getLogger(noisy).setLevel(logging.WARNING)
    run(args.host, args.port, args.tick_seconds)


if __name__ == "__main__":
    main()
