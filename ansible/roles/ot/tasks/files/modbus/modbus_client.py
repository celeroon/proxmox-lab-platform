"""Modbus/TCP client simulating an HMI/operator polling and controlling the tank.

Standalone run (production / systemd):
    python3 modbus_client.py --host 10.2.0.10 --port 502

poll_once() is reused directly by the local round-trip test.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import random
from dataclasses import dataclass

from pymodbus.client import AsyncModbusTcpClient

from modbus_logic import (
    COIL_PUMP_RUN,
    DEFAULT_ALARM_THRESHOLD,
    DISCRETE_HIGH_ALARM,
    HOLDING_ALARM_THRESHOLD,
    HOLDING_LEVEL,
    level_to_register,
    register_to_level,
)

log = logging.getLogger("modbus_client")

LOW_SETPOINT = 20.0   # below this, start the pump
HIGH_SETPOINT = 80.0  # above this, stop the pump

# Fire low-frequency FCs every N polls to populate Malcolm dashboard panels
# that only appear when those function codes are observed.
_RARE_FC_EVERY = 40   # ~200 s at default 5 s poll

# Zeek/Suricata only write a conn.log/flow entry when a TCP connection *closes* —
# never while it's ongoing. A permanently-open connection (the natural behavior for
# a real HMI) means "Modbus - Transport" and any other panel filtering on
# event.dataset:conn never shows this session as "recent", even with continuous
# activity. Reconnecting periodically trades a little realism for dashboard
# visibility — confirmed live 2026-07-03 that a closed connection produces an
# immediate conn.log row.
_RECONNECT_EVERY = 36   # ~180 s at default 5 s poll


@dataclass
class TankReading:
    level: float
    high_alarm: bool
    pump_on: bool


async def poll_once(client: AsyncModbusTcpClient) -> TankReading:
    level_rr = await client.read_holding_registers(HOLDING_LEVEL, count=1, slave=1)
    alarm_rr = await client.read_discrete_inputs(DISCRETE_HIGH_ALARM, count=1, slave=1)
    level = register_to_level(level_rr.registers[0])
    high_alarm = bool(alarm_rr.bits[0])

    pump_on = level < LOW_SETPOINT
    if level >= LOW_SETPOINT and level <= HIGH_SETPOINT:
        # mid-band: leave the pump in whatever state it was already commanded to
        coil_rr = await client.read_coils(COIL_PUMP_RUN, count=1, slave=1)
        pump_on = bool(coil_rr.bits[0])
    elif level > HIGH_SETPOINT:
        pump_on = False

    await client.write_coil(COIL_PUMP_RUN, pump_on, slave=1)
    return TankReading(level=level, high_alarm=high_alarm, pump_on=pump_on)


async def fire_rare_fcs(client: AsyncModbusTcpClient, poll_count: int) -> None:
    """Fire rarely-used Modbus FCs so Malcolm dashboard panels are populated.

    FC 22 (Mask Write Register) → modbus_mask_write_register.log
    FC 23 (Read/Write Multiple Registers) → modbus_read_write_multiple_registers.log
    FC 43 subcode 14 (Read Device Identification) → modbus_read_device_identification.log
    """
    if poll_count % _RARE_FC_EVERY != 0:
        return

    # FC 22 — Mask Write Register: apply a no-op bitmask to alarm threshold register
    try:
        await client.mask_write_register(
            address=HOLDING_ALARM_THRESHOLD,
            and_mask=0xFFFF,
            or_mask=0x0000,
            slave=1,
        )
    except Exception as exc:
        log.debug("FC22 mask_write_register: %s", exc)

    # FC 23 — Read/Write Multiple Registers: atomic read of level + reset alarm threshold
    # pymodbus 3.7.4's client method is `readwrite_registers` (no underscore between
    # read/write) and takes the write payload as `values`, not `write_registers` —
    # the previous names raised AttributeError on every call, silently swallowed
    # below, so this FC never actually reached the wire.
    try:
        await client.readwrite_registers(
            read_address=HOLDING_LEVEL,
            read_count=1,
            write_address=HOLDING_ALARM_THRESHOLD,
            values=[level_to_register(DEFAULT_ALARM_THRESHOLD)],
            slave=1,
        )
    except Exception as exc:
        log.debug("FC23 readwrite_registers: %s", exc)

    # FC 43/subcode 14 — Read Device Identification
    # Server may return exception 0x01 (illegal function) — Zeek still logs the request.
    try:
        await client.read_device_information(read_code=0x01, object_id=0x00, slave=1)
    except Exception as exc:
        log.debug("FC43 read_device_information: %s", exc)


async def maybe_reconnect(client: AsyncModbusTcpClient, poll_count: int) -> None:
    """Periodically close and reopen the connection so Zeek/Suricata log it.

    See _RECONNECT_EVERY's comment for why this is needed at all.
    """
    if poll_count % _RECONNECT_EVERY != 0:
        return

    client.close()
    await asyncio.sleep(0.5)
    await client.connect()


async def external_probe_loop(ip: str, port: int) -> None:
    """Periodically perform a real Modbus read against ip:port to generate
    external-destination ICS traffic visible to Malcolm's 'ICS/IoT External
    Traffic' dashboard panel.

    A bare TCP connect+close is NOT enough: the panel filters on the
    `ics`/`ics_best_guess` tags, and Malcolm's logstash pipeline only applies
    `ics` when Zeek's modbus analyzer actually classifies the session as
    modbus (a real protocol exchange), never for a plain SYN/RST with no
    payload. Confirmed live 2026-07-04: a bare TCP probe produced a conn.log
    entry with service="-" and empty tags, so the panel stayed empty despite
    the session existing. `ip` is expected to be a VyOS loopback address
    (e.g. 9.9.9.9) with a hairpin DNAT redirecting this exact flow back to
    the real modbus-server (see `vyos/configure_external_traffic_redirect`) —
    so this read genuinely succeeds against real tank data, while Zeek's
    mirror still sees the pre-NAT external destination.
    """
    while True:
        delay = random.uniform(60, 300)   # 1–5 minutes
        await asyncio.sleep(delay)
        probe_client = AsyncModbusTcpClient(ip, port=port)
        try:
            await asyncio.wait_for(probe_client.connect(), timeout=5.0)
            await probe_client.read_holding_registers(HOLDING_LEVEL, count=1, slave=1)
        except Exception:
            pass  # connection/read failure is fine — the exchange attempt is what Malcolm needs
        finally:
            probe_client.close()


async def run(
    host: str,
    port: int,
    poll_seconds: float,
    external_probe_ip: str | None = None,
    external_probe_port: int = 502,
) -> None:
    client = AsyncModbusTcpClient(host, port=port)
    await client.connect()

    background: list[asyncio.Task] = []
    if external_probe_ip:
        background.append(
            asyncio.create_task(external_probe_loop(external_probe_ip, external_probe_port))
        )

    poll_count = 0
    try:
        while True:
            reading = await poll_once(client)
            await fire_rare_fcs(client, poll_count)
            poll_count += 1
            log.info(
                "level=%.1f%% pump_on=%s high_alarm=%s",
                reading.level,
                reading.pump_on,
                reading.high_alarm,
            )
            await maybe_reconnect(client, poll_count)
            await asyncio.sleep(poll_seconds)
    finally:
        for t in background:
            t.cancel()
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus tank+pump HMI/operator simulator")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--log-file", default=None, help="also write logs here (tail -f friendly)")
    parser.add_argument(
        "--external-probe-ip",
        default=None,
        help="IP to probe every 1-5 min to generate 'external' traffic visible in Malcolm",
    )
    parser.add_argument("--external-probe-port", type=int, default=502)
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", handlers=handlers)
    asyncio.run(
        run(
            args.host,
            args.port,
            args.poll_seconds,
            external_probe_ip=args.external_probe_ip,
            external_probe_port=args.external_probe_port,
        )
    )


if __name__ == "__main__":
    main()
