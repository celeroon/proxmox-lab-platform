"""PROFINET engineering-station simulator ("profinet-client") — periodically
resolves profinet-server via real DCP discovery (same L2 segment, unlike
kali-1's cross-VLAN workaround — see profinet_logic.py's module docstring)
and establishes a real, unauthorized-free AR-Connect with IOCR (cyclic-IO)
negotiation, the same way a real SCADA/engineering station repeatedly tries
to (re)establish its connection to a PLC.

Does not attempt PrmEnd/ApplicationReady/live cyclic data — p-net aborts that
next step with a real-time alarm ("PDev: no port offers required
speed/duplexity") since virtio virtual NICs don't report a real link speed
(see profinet_logic.py's module docstring for the full story). Stopping at a
successful AR/IOCR-negotiate-then-release keeps this poller simple and
reliable for a long-running systemd service, while still generating the same
rich, real, Zeek-visible profinet.log / profinet_io_cm.log traffic every
cycle (ARBlockReq/ARBlockRes, IOCRBlockReq/Res, AlarmCRBlockReq/Res, then a
clean Release) that the custom OpenSearch Alerting monitor and dashboard key
on — this is the "legitimate" baseline traffic the monitor's source-IP
exclusion is built against.

Usage:
    python3 profinet_client.py --target profinet-server --interface eth1 \\
        --poll-seconds 30 --log-file /var/log/profinet-client.log
"""

from __future__ import annotations

import argparse
import logging
import time

from profinet_logic import DEFAULT_SLOT, resolve_device, unauthorized_iocr_connect

log = logging.getLogger("profinet_client")


def poll_once(attempt: int, station_name: str, interface: str) -> None:
    try:
        info, src_mac = resolve_device(station_name, interface)
    except Exception as exc:
        log.error("AR-Connect attempt #%d: FAILED to resolve %s via DCP -- %s", attempt, station_name, exc)
        return

    conn = None
    try:
        conn, result = unauthorized_iocr_connect(info, src_mac, DEFAULT_SLOT)
        log.info(
            "AR-Connect attempt #%d: SUCCESS has_cyclic=%s input_frame_id=%s output_frame_id=%s",
            attempt,
            getattr(result, "has_cyclic", None),
            getattr(result, "input_frame_id", None),
            getattr(result, "output_frame_id", None),
        )
    except Exception as exc:
        log.error("AR-Connect attempt #%d: FAILED -- %s", attempt, exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="PROFINET legitimate engineering-station poller")
    parser.add_argument("--target", default="profinet-server", help="PROFINET station name to resolve via DCP")
    parser.add_argument("--interface", default="eth1", help="Network interface to use")
    parser.add_argument("--poll-seconds", type=float, default=30.0, help="Seconds between AR-Connect attempts")
    parser.add_argument("--log-file", default=None, help="Optional log file path (also logs to stdout)")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", handlers=handlers)

    attempt = 0
    while True:
        attempt += 1
        poll_once(attempt, args.target, args.interface)
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
