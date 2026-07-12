from __future__ import annotations

import subprocess
from pathlib import Path

_DNSMASQ_DIR = Path("/etc/dnsmasq.d")
# Hosts files live outside conf-dir so dnsmasq does not parse them as config.
# Debian's dnsmasq.conf loads all files in /etc/dnsmasq.d/ regardless of extension;
# a hosts file containing "mac,ip" lines would trigger "bad option" parse errors.
_HOSTS_DIR = Path("/var/lib/dnsmasq")


def user_conf_content(user_id: int, gateway: str, dhcp_start: str, dhcp_end: str) -> str:
    """Generate the per-user dnsmasq conf fragment (pure, no side effects).

    dhcp-hostsfile: reservations live in a separate file that dnsmasq re-reads
    on SIGHUP (reload) — avoids a full restart on every VM deploy/destroy.

    dhcp-authoritative: when a VM has a stale DHCP lease for a different IP,
    dnsmasq NAKs the renewal immediately so the VM retries with DISCOVER and
    receives its reserved address.  Without this, dnsmasq silently ignores the
    conflicting request and the VM keeps the wrong IP.

    dhcp-option is tagged to this user's own range (set:/tag:): an untagged
    dhcp-option=3,<gw> is global across every interface dnsmasq serves, not
    scoped to the interface= line above it — with one fragment per user under
    /etc/dnsmasq.d/, the last-loaded file's gateway would silently win for
    every user's clients. Tagging keeps each user's gateway scoped to leases
    from their own range only.
    """
    return (
        f"interface=mgmt{user_id}\n"
        f"dhcp-range=set:mgmt{user_id},{dhcp_start},{dhcp_end},255.255.0.0,24h\n"
        f"dhcp-option=tag:mgmt{user_id},3,{gateway}\n"
        f"dhcp-hostsfile={_HOSTS_DIR}/mgmt-{user_id}.hosts\n"
        f"dhcp-authoritative\n"
    )


def write_user_conf(user_id: int, gateway: str, dhcp_start: str, dhcp_end: str) -> None:
    """Write the per-user dnsmasq conf + empty hostsfile, then restart dnsmasq.

    A full restart (not reload) is required because adding a new dhcp-range
    causes dnsmasq to open port 67 for the first time on this interface.
    HUP/reload re-reads config but does not open new sockets.
    """
    content = user_conf_content(user_id, gateway, dhcp_start, dhcp_end)
    _tee(_DNSMASQ_DIR / f"mgmt-{user_id}.conf", content)
    _tee(_HOSTS_DIR / f"mgmt-{user_id}.hosts", "")
    subprocess.run(["sudo", "systemctl", "restart", "dnsmasq"], check=True)


def remove_user_conf(user_id: int) -> None:
    """Remove the per-user dnsmasq conf + hostsfile, then restart dnsmasq.

    A full restart (not reload) is required to close port 67 on mgmt{N} and
    flush the dhcp-range from memory — SIGHUP does not unload DHCP config.
    """
    subprocess.run(["sudo", "rm", "-f", str(_DNSMASQ_DIR / f"mgmt-{user_id}.conf")], check=True)
    subprocess.run(["sudo", "rm", "-f", str(_HOSTS_DIR / f"mgmt-{user_id}.hosts")], check=True)
    subprocess.run(["sudo", "systemctl", "restart", "dnsmasq"], check=True)


def add_dhcp_host(user_id: int, mac: str, ip: str) -> None:
    """Append a MAC→IP reservation to the per-user hostsfile and reload dnsmasq.

    dnsmasq re-reads dhcp-hostsfiles on SIGHUP so a reload (not restart) is
    sufficient.  dhcp-authoritative in the conf handles any stale lease: the VM
    receives a NAK and immediately retries with DISCOVER to get the reserved IP.
    """
    line = f"{mac},{ip}\n"
    subprocess.run(
        ["sudo", "tee", "-a", str(_HOSTS_DIR / f"mgmt-{user_id}.hosts")],
        input=line, text=True, check=True, capture_output=True,
    )
    subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=True)


def add_dhcp_hosts_bulk(user_id: int, entries: list[tuple[str, str]]) -> None:
    """Append multiple MAC→IP reservations to the per-user hostsfile in one write, then reload dnsmasq."""
    if not entries:
        return
    content = "".join(f"{mac},{ip}\n" for mac, ip in entries)
    subprocess.run(
        ["sudo", "tee", "-a", str(_HOSTS_DIR / f"mgmt-{user_id}.hosts")],
        input=content, text=True, check=True, capture_output=True,
    )
    subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=True)


def remove_dhcp_host(user_id: int, mac: str) -> None:
    """Remove the MAC→IP reservation from the per-user hostsfile and reload dnsmasq."""
    hosts_path = _HOSTS_DIR / f"mgmt-{user_id}.hosts"
    subprocess.run(
        ["sudo", "sed", "-i", f"/^{mac},/Id", str(hosts_path)],
        check=True,
    )
    subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=True)


def _tee(path: Path, content: str) -> None:
    subprocess.run(
        ["sudo", "tee", str(path)],
        input=content, text=True, check=True, capture_output=True,
    )
