"""BACnet client simulating a supervisory BAS watching the HVAC zone.

Standalone run (production / systemd):
    python3 bacnet_client.py --host 10.2.0.14 --port 47808

Purely supervisory — reads Temperature, occasionally nudges Setpoint, but
never touches UnitRunning itself (that's the RTU's own autonomous hysteresis
loop, same as a real local thermostat). Uses BAC0's read() (reliable,
confirmed by direct testing) and the underlying _write() coroutine instead of
the public write() wrapper, which is a fire-and-forget background task with
no confirmation — confirmed unreliable by direct testing (a write via
write() + a short sleep did not reliably show up on a subsequent read;
calling _write() directly did, every time).

poll_once()/adjust_setpoint() are reused directly by the local round-trip test.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import random
import time
from dataclasses import dataclass

import BAC0

from bacnet_logic import SETPOINT_INSTANCE, TAG_TEMPERATURE, TEMPERATURE_INSTANCE

log = logging.getLogger("bacnet_client")

SETPOINTS = [22.0, 18.0]
ADJUST_EVERY_N_POLLS = 8
EXTERNAL_PROBE_MIN_DELAY = 60   # 1-5 minutes, matching modbus_client.py/s7_client.py's external probe
EXTERNAL_PROBE_MAX_DELAY = 300


@dataclass
class ZoneReading:
    temperature: float


def _addr(host: str, port: int) -> str:
    return f"{host}:{port}"


async def poll_once(client: BAC0.lite, host: str, port: int) -> ZoneReading:
    temp = await client.read(f"{_addr(host, port)} analogValue {TEMPERATURE_INSTANCE} presentValue")
    return ZoneReading(temperature=float(temp))


async def adjust_setpoint(client: BAC0.lite, host: str, port: int, new_setpoint: float) -> None:
    await client._write(
        f"{_addr(host, port)} analogValue {SETPOINT_INSTANCE} presentValue {new_setpoint} - 8"
    )


async def external_probe(bind_host: str, ip: str, port: int) -> None:
    """Perform a real BACnet read against ip:port to generate external-destination
    ICS traffic visible to Malcolm's 'ICS/IoT External Traffic' dashboard panel.

    Same rationale as modbus_client.py/s7_client.py's external_probe -- a bare
    packet never gets tagged `ics`/`ics_best_guess`, only a genuine protocol
    exchange does. `ip` is expected to be a VyOS loopback (9.9.9.9) with a hairpin
    DNAT redirecting this exact flow back to the real bacnet-server, so this read
    genuinely succeeds against real Temperature data while Zeek's mirror still
    sees the pre-NAT external destination. Uses its own short-lived BAC0 instance
    on a distinct bind port (never the main polling client's) -- BAC0.lite() binds
    its own UDP socket, so a second instance on the same host needs a different
    port to avoid a bind conflict. BACnet/IP is connectionless UDP, so unlike
    S7comm there's no shared-connection parser-desync risk here; the separate
    instance is just to keep this probe's traffic clearly distinct in the logs.
    """
    probe = BAC0.lite(ip=bind_host, port=port + 1)
    await asyncio.sleep(0.3)
    try:
        await probe.read(f"{ip}:{port} analogValue {TEMPERATURE_INSTANCE} presentValue")
    except Exception:
        pass  # connection/read failure is fine -- the exchange attempt is what Malcolm needs
    finally:
        probe.disconnect()


async def run(
    host: str,
    port: int,
    bind_host: str,
    bind_port: int,
    poll_seconds: float,
    external_probe_ip: str | None = None,
    external_probe_port: int = 47808,
) -> None:
    client = BAC0.lite(ip=bind_host, port=bind_port)
    await asyncio.sleep(0.5)
    next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)
    try:
        poll_index = 0
        setpoint_idx = 0
        last_commanded_setpoint: float | None = None  # for the TUI only, see bacnet_tui_common.py
        while True:
            reading = await poll_once(client, host, port)
            # commanded_setpoint is additive for bacnet_client_tui.py -- the regular
            # poll line otherwise only carries Temperature, unlike the server's tick
            # line which already has all three points.
            log.info(
                "%s=%.1f commanded_setpoint=%s",
                TAG_TEMPERATURE,
                reading.temperature,
                f"{last_commanded_setpoint:.1f}" if last_commanded_setpoint is not None else "-",
            )

            if poll_index > 0 and poll_index % ADJUST_EVERY_N_POLLS == 0:
                setpoint_idx = (setpoint_idx + 1) % len(SETPOINTS)
                new_setpoint = SETPOINTS[setpoint_idx]
                await adjust_setpoint(client, host, port, new_setpoint)
                last_commanded_setpoint = new_setpoint
                log.info("routine setpoint adjustment -> %.1f", new_setpoint)

            if external_probe_ip and time.time() >= next_probe_time:
                await external_probe(bind_host, external_probe_ip, external_probe_port)
                next_probe_time = time.time() + random.uniform(EXTERNAL_PROBE_MIN_DELAY, EXTERNAL_PROBE_MAX_DELAY)

            poll_index += 1
            await asyncio.sleep(poll_seconds)
    finally:
        client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="BACnet supervisory BAS simulator")
    parser.add_argument("--host", required=True, help="the BACnet field device's address")
    parser.add_argument("--port", type=int, default=47808, help="the BACnet field device's port")
    parser.add_argument(
        "--bind-host",
        default="127.0.0.1",
        help="this client's own concrete local IP, never 0.0.0.0 — bacpypes3 fails to "
        "bind its broadcast socket with the wildcard address (confirmed by direct "
        "testing). On a real VM, pass its actual management IP.",
    )
    parser.add_argument(
        "--bind-port",
        type=int,
        default=47808,
        help="this client's own BACnet port — only needs to differ from --port "
        "when client and server run on the same machine (loopback testing)",
    )
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    parser.add_argument(
        "--external-probe-ip",
        default=None,
        help="IP to probe every 1-5 min to generate 'external' traffic visible in Malcolm",
    )
    parser.add_argument("--external-probe-port", type=int, default=47808)
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    for noisy in ("BAC0_Root", "bacpypes3"):  # BAC0's actual top-level logger is "BAC0_Root", not "BAC0"
        logging.getLogger(noisy).setLevel(logging.WARNING)
    asyncio.run(
        run(
            args.host,
            args.port,
            args.bind_host,
            args.bind_port,
            args.poll_seconds,
            external_probe_ip=args.external_probe_ip,
            external_probe_port=args.external_probe_port,
        )
    )


if __name__ == "__main__":
    main()
