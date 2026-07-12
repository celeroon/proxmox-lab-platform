"""
Platform garbage collection — finds and removes orphaned resources left by crashes
or interrupted operations.

Orphan categories
-----------------
operations    : status 'running'/'started' > 2 h old → mark failed
templates     : VMID 9000–9999 in Proxmox, not yet converted to template → delete
hot_templates : VMID 20001–99999 in Proxmox, no hot_templates DB row → delete
user_vms      : VMID ≥ 100000 in Proxmox, no vms DB row → stop + delete (platform-owned range)
vnets         : labzone/labmgmt VNets in Proxmox, no DB record → delete
dnsmasq       : MAC entries in hostsfiles with no matching vms row → remove
mgmt_nics     : NICs on the management VM with user MAC pattern, user not in DB → remove
"""
from __future__ import annotations

import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from lab.db import get_conn
from lab.proxmox import ProxmoxClient
from lab.users import _subnet_cidr

_HOSTS_DIR = Path("/var/lib/dnsmasq")

# Proxmox/Ceph serialize CT/VM delete (RBD removal) behind a single cluster-wide
# 'storage-ceph-pool' cfs-lock — high delete concurrency just causes most threads
# to lose the lock race and fail, leaving stragglers across repeated gc runs.
_DELETE_WORKERS = 4

_TEMPLATE_VMID_MIN  = 9_000
_TEMPLATE_VMID_MAX  = 9_999
_HOT_VMID_MIN       = 20_001
_HOT_VMID_MAX       = 99_999
_USER_VMID_MIN      = 100_000

# Matches labzone VNets: v + exactly 8 hex chars (e.g. v0200001a)
_LABZONE_RE  = re.compile(r"^v[0-9a-f]{8}$")
# Matches labmgmt VNets: mgmt + one or more digits (e.g. mgmt2)
_LABMGMT_RE  = re.compile(r"^mgmt(\d+)$")
# Matches the management-VM NIC MAC pattern: 52:54:ff:XX:00:00
_MGMT_NIC_RE = re.compile(r"52:54:ff:([0-9a-f]{2}):00:00", re.IGNORECASE)


LogFn = Callable[[str], None]


def run_gc(
    proxmox: ProxmoxClient,
    mgmt_vmid: int,
    dry_run: bool = False,
    log_fn: LogFn = print,
) -> dict[str, int]:
    """Run a full GC pass. Returns {category: count_affected}."""
    prefix = "[dry-run] " if dry_run else ""
    results: dict[str, int] = {
        "operations":    _gc_operations(dry_run, log_fn, prefix),
        "templates":     _gc_template_vmids(proxmox, dry_run, log_fn, prefix),
        "hot_templates": _gc_hot_template_vmids(proxmox, dry_run, log_fn, prefix),
        "user_vms":      _gc_user_vmids(proxmox, dry_run, log_fn, prefix),
        "vnets":         _gc_vnets(proxmox, dry_run, log_fn, prefix),
        "dnsmasq":       _gc_dnsmasq(dry_run, log_fn, prefix),
        "mgmt_nics":     _gc_mgmt_nics(proxmox, mgmt_vmid, dry_run, log_fn, prefix),
    }
    return results


# ── operations ────────────────────────────────────────────────────────────────

def _gc_operations(dry_run: bool, log_fn: LogFn, prefix: str) -> int:
    """Mark stuck operations (running/started > 2 h) as failed."""
    count = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, type, command, started_at FROM operations "
                "WHERE status IN ('running', 'started') "
                "AND started_at < NOW() - INTERVAL '2 hours'"
            )
            rows = cur.fetchall()
        for row in rows:
            log_fn(
                f"{prefix}stuck operation {row['id']} "
                f"({row['type']}: {row['command']!r}, started {row['started_at']}) → mark failed"
            )
            if not dry_run:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE operations SET status='failed', completed_at=NOW() WHERE id=%s",
                        (row["id"],),
                    )
                conn.commit()
            count += 1
    return count


# ── template VMIDs (9000–9999) ────────────────────────────────────────────────

def _gc_template_vmids(proxmox: ProxmoxClient, dry_run: bool, log_fn: LogFn, prefix: str) -> int:
    """Delete QEMU VMs in 9000–9999 that were never converted to templates."""
    count = 0
    for r in proxmox.get_cluster_resources("vm"):
        vmid = r.get("vmid", 0)
        if not (_TEMPLATE_VMID_MIN <= vmid <= _TEMPLATE_VMID_MAX):
            continue
        if r.get("template", 0) == 1:
            continue  # fully converted — fine
        node = r.get("node", "")
        name = r.get("name", "")
        log_fn(f"{prefix}orphan template VMID {vmid} ({name!r} on {node}) — not converted to template, deleting")
        if not dry_run:
            try:
                proxmox.stop_vm(node, vmid, wait=True)
            except Exception:
                pass
            try:
                proxmox.delete_vm(node, vmid, wait=True)
            except Exception as exc:
                log_fn(f"  failed to delete VMID {vmid}: {exc}")
                continue
        count += 1
    return count


# ── hot template VMIDs (20001–99999) ─────────────────────────────────────────

def _gc_hot_template_vmids(proxmox: ProxmoxClient, dry_run: bool, log_fn: LogFn, prefix: str) -> int:
    """Delete VMs in the hot-template range with no matching hot_templates row."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT vmid FROM hot_templates WHERE vmid IS NOT NULL")
            known_vmids = {row["vmid"] for row in cur.fetchall()}

    count = 0
    for r in proxmox.get_cluster_resources("vm"):
        vmid = r.get("vmid", 0)
        if not (_HOT_VMID_MIN <= vmid <= _HOT_VMID_MAX):
            continue
        if vmid in known_vmids:
            continue
        node = r.get("node", "")
        name = r.get("name", "")
        log_fn(f"{prefix}orphan hot-template VMID {vmid} ({name!r} on {node}) — no DB record, deleting")
        if not dry_run:
            try:
                proxmox.stop_vm(node, vmid, wait=True)
            except Exception:
                pass
            try:
                proxmox.delete_vm(node, vmid, wait=True)
            except Exception as exc:
                log_fn(f"  failed to delete VMID {vmid}: {exc}")
                continue
        count += 1
    return count


# ── user VMs (≥ 100000) ───────────────────────────────────────────────────────

def _gc_user_vmids(proxmox: ProxmoxClient, dry_run: bool, log_fn: LogFn, prefix: str) -> int:
    """Delete user-range VMIDs in Proxmox with no DB record.

    VMIDs ≥ 100000 are exclusively assigned by the platform per user, so any
    entry in this range without a matching vms row is a leaked platform VM —
    safe to stop and delete automatically.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT vmid FROM vms")
            known_vmids = {row["vmid"] for row in cur.fetchall()}

    orphans = []
    for r in proxmox.get_cluster_resources("vm"):
        vmid = r.get("vmid", 0)
        if vmid < _USER_VMID_MIN:
            continue
        if vmid in known_vmids:
            continue
        orphans.append({
            "vmid":  vmid,
            "node":  r.get("node", ""),
            "name":  r.get("name", ""),
            "is_ct": r.get("type", "qemu") == "lxc",
        })

    for o in orphans:
        kind = "CT" if o["is_ct"] else "VM"
        log_fn(f"{prefix}orphan user {kind} VMID {o['vmid']} ({o['name']!r} on {o['node']}) — not in DB, deleting")

    if not dry_run and orphans:
        # Stop first, in parallel — not storage-bound, safe at full concurrency.
        def _stop(o: dict) -> None:
            vmid, node, is_ct = o["vmid"], o["node"], o["is_ct"]
            try:
                if is_ct:
                    proxmox.stop_ct(node, vmid, wait=True)
                else:
                    proxmox.stop_vm(node, vmid, wait=True)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(len(orphans), 16)) as pool:
            list(pool.map(_stop, orphans))

        # Delete with retry/backoff and limited concurrency — Proxmox/Ceph
        # serialize storage deletes behind one cfs-lock, so most parallel
        # attempts beyond a handful just lose the lock race and fail.
        def _delete(o: dict) -> tuple[int, str | None]:
            vmid, node, is_ct = o["vmid"], o["node"], o["is_ct"]
            for _attempt in range(1, 4):
                try:
                    if is_ct:
                        proxmox.delete_ct(node, vmid, wait=True)
                    else:
                        proxmox.delete_vm(node, vmid, wait=True)
                    return vmid, None
                except Exception as exc:
                    if "cfs-lock" in str(exc) and _attempt < 3:
                        time.sleep(5)
                    else:
                        return vmid, str(exc)
            return vmid, None

        with ThreadPoolExecutor(max_workers=min(len(orphans), _DELETE_WORKERS)) as pool:
            futures = {pool.submit(_delete, o): o["vmid"] for o in orphans}
            for fut in as_completed(futures):
                vmid, err = fut.result()
                if err:
                    log_fn(f"  failed to delete VMID {vmid}: {err}")

    return len(orphans)


# ── VNets ─────────────────────────────────────────────────────────────────────

def _gc_vnets(proxmox: ProxmoxClient, dry_run: bool, log_fn: LogFn, prefix: str) -> int:
    """Delete labzone/labmgmt VNets in Proxmox with no matching DB record."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT vnet FROM networks WHERE vnet IS NOT NULL")
            known_scenario_vnets = {row["vnet"] for row in cur.fetchall()}
            cur.execute("SELECT user_id FROM users")
            known_user_ids = {row["user_id"] for row in cur.fetchall()}

    count = 0
    try:
        vnets = proxmox.list_vnets()
    except Exception as exc:
        log_fn(f"could not list VNets from Proxmox: {exc}")
        return 0

    sdn_dirty = False
    for vnet in vnets:
        vnet_id = vnet.get("vnet", "")
        zone    = vnet.get("zone", "")

        if zone == "labzone" and _LABZONE_RE.match(vnet_id):
            if vnet_id not in known_scenario_vnets:
                log_fn(f"{prefix}orphan labzone VNet {vnet_id} — no DB record, deleting")
                if not dry_run:
                    try:
                        proxmox.delete_vnet(vnet_id)
                        sdn_dirty = True
                    except Exception as exc:
                        log_fn(f"  failed to delete {vnet_id}: {exc}")
                        continue
                count += 1

        elif zone == "labmgmt" and (m := _LABMGMT_RE.match(vnet_id)):
            uid = int(m.group(1))
            if uid not in known_user_ids:
                log_fn(f"{prefix}orphan labmgmt VNet {vnet_id} (user_id={uid}) — user not in DB, deleting")
                if not dry_run:
                    # Proxmox refuses to delete a VNet while its subnet object still
                    # exists ("400 Parameter verification failed") — subnet first,
                    # same order users.py's delete() uses for a normal user deletion.
                    try:
                        proxmox.delete_subnet(vnet_id, _subnet_cidr(uid))
                    except Exception as exc:
                        log_fn(f"  warning: delete subnet for {vnet_id} failed: {exc}")
                    try:
                        proxmox.delete_vnet(vnet_id)
                        sdn_dirty = True
                    except Exception as exc:
                        log_fn(f"  failed to delete {vnet_id}: {exc}")
                        continue
                count += 1

    if sdn_dirty:
        try:
            proxmox.apply_sdn()
        except Exception as exc:
            log_fn(f"warning: SDN apply after VNet cleanup failed: {exc}")

    return count


# ── dnsmasq hostsfiles ────────────────────────────────────────────────────────

def _gc_dnsmasq(dry_run: bool, log_fn: LogFn, prefix: str) -> int:
    """Remove stale MAC→IP entries from hostsfiles where the MAC is not in the vms table."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT mac_address FROM vms WHERE mac_address IS NOT NULL")
            known_macs = {row["mac_address"].lower() for row in cur.fetchall()}
            cur.execute("SELECT user_id FROM users")
            user_ids = [row["user_id"] for row in cur.fetchall()]

    count = 0
    for uid in user_ids:
        hosts_path = _HOSTS_DIR / f"mgmt-{uid}.hosts"
        if not hosts_path.exists():
            continue
        try:
            lines = hosts_path.read_text().splitlines()
        except PermissionError:
            log_fn(f"cannot read {hosts_path} — run as root or with sudo")
            continue

        keep, removed = [], []
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            mac = line.split(",")[0].lower()
            if mac in known_macs:
                keep.append(line)
            else:
                log_fn(f"{prefix}stale dnsmasq entry mgmt-{uid}.hosts: {line} — MAC not in DB")
                removed.append(line)
                count += 1

        if removed and not dry_run:
            new_content = "\n".join(keep) + ("\n" if keep else "")
            subprocess.run(
                ["sudo", "tee", str(hosts_path)],
                input=new_content, text=True, check=True, capture_output=True,
            )
            subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=True)

    return count


# ── management VM NICs ────────────────────────────────────────────────────────

def _gc_mgmt_nics(proxmox: ProxmoxClient, mgmt_vmid: int, dry_run: bool, log_fn: LogFn, prefix: str) -> int:
    """Remove NICs on the management VM whose user_id (encoded in the MAC) has no DB record."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM users")
            known_user_ids = {row["user_id"] for row in cur.fetchall()}

    try:
        node = proxmox.find_vm_node(mgmt_vmid)
    except Exception:
        return 0  # mgmt VM not found (e.g. running outside Proxmox in dev)

    try:
        config = proxmox.get_vm_config(node, mgmt_vmid)
    except Exception as exc:
        log_fn(f"could not read VMID {mgmt_vmid} config: {exc}")
        return 0

    count = 0
    for key, value in config.items():
        if not key.startswith("net"):
            continue
        m = _MGMT_NIC_RE.search(str(value))
        if not m:
            continue
        uid = int(m.group(1), 16)
        if uid in known_user_ids:
            continue
        log_fn(f"{prefix}orphan mgmt NIC slot {key} on VMID {mgmt_vmid} (user_id={uid}) — user not in DB, removing")
        if not dry_run:
            try:
                proxmox.remove_nic(node, mgmt_vmid, key)
            except Exception as exc:
                log_fn(f"  failed to remove {key}: {exc}")
                continue
        count += 1

    return count
