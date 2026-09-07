from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx
import yaml

from lab import dnsmasq, ids
from lab.config import Settings, get_settings
from lab.db import get_conn
from lab.proxmox import ProxmoxClient
from lab.scenario import NetworkSpec, ScenarioSpec, VMSpec, execution_plan, parse_scenario
from lab.scheduler import schedule
from lab.templates import TemplateManager

_PROJECT_ROOT = Path(__file__).parent.parent
_ANSIBLE_DIR = _PROJECT_ROOT / "ansible"


_ROLES_DIR = _ANSIBLE_DIR / "roles"
_SCENARIOS_DIR = _PROJECT_ROOT / "scenarios"

# The single, fixed name for a VM's clean-baseline snapshot (the reset pivot for the
# detonation range). Users never type it; per-VM naming means no cross-lab collision.
BASELINE_SNAPSHOT = "clean-baseline"

# Proxmox/Ceph serialize CT/VM delete (RBD removal) behind a single cluster-wide
# 'storage-ceph-pool' cfs-lock. High delete concurrency just causes most threads
# to lose the lock race and fail — keep this well below the stop/create worker
# counts, which aren't storage-bound and can stay parallel.
_DELETE_WORKERS = 4


def _is_already_running_error(exc: Exception) -> bool:
    """True if a start_ct/start_vm call failed because the guest is already running.

    Happens when a prior retry attempt's create+start actually succeeded on Proxmox,
    but the client never saw a clean response (broken pipe, TLS hiccup, dropped
    connection) and treated it as a transient failure worth retrying. The retry then
    re-issues start_ct/start_vm against a guest that's already up — that's the goal
    state, not a failure, and should not abort the deployment.
    """
    return "already running" in str(exc).lower()


def _normalize_prior_status(status: str) -> str:
    """Normalize a deployment's status before reusing it for a --target add.

    A 'failed' status here only means a previous --target add attempt failed before
    creating anything new — the deployment's existing VMs are otherwise healthy
    (that's the precondition for allowing --target reuse on 'failed' at all; see the
    comment where this is called). Normalize it to 'active' so a repeatedly-failing
    add doesn't re-propagate 'failed' forever via _status_after_failed_start — without
    this, a deployment that failed once would stay invisible to status filters on
    every subsequent failed retry too.
    """
    return "active" if status == "failed" else status


def _status_after_failed_start(prior_status: str | None) -> str:
    """Status to apply when start() raises.

    prior_status is the deployment's status before this start() call, captured only
    for incremental --target adds to an already-existing deployment. A failed add
    (e.g. ran out of RAM headroom before creating anything new) leaves that
    deployment's existing VMs untouched, so its status should revert to whatever it
    was — not get stamped 'failed', which would hide those VMs from lab status /
    lab deploy status (both filter on status). A fresh first-time deploy has no prior
    state to revert to, so 'failed' is correct there.
    """
    return prior_status if prior_status is not None else "failed"


# ── Step 2: VM index allocation ───────────────────────────────────────────────

def _vm_index_from_mac(mac: str) -> int | None:
    """Parse vm_index from a management NIC MAC. Returns None if the MAC should be skipped.

    Management NIC MACs have the form 52:54:{user_id:02x}:{vm_hi:02x}:{vm_lo:02x}:00.
    Skip conditions:
      - parts[5] != "00"  → not a management NIC (iface_index != 0)
      - parts[2] == "ff"  → mgmt VM NIC (52:54:ff:...), not a lab VM NIC
    """
    parts = mac.split(":")
    if len(parts) != 6:
        return None
    if parts[5] != "00":
        return None
    if parts[2] == "ff":
        return None
    return (int(parts[3], 16) << 8) | int(parts[4], 16)


def _next_base_from_macs(macs: list[str]) -> int:
    """Return the next base_vm_index given a list of MAC addresses.

    Parses vm_index from each management NIC MAC and returns max(vm_indexes) + 1,
    or 0 if no valid management NIC MACs are present.
    """
    indexes = [idx for mac in macs if (idx := _vm_index_from_mac(mac)) is not None]
    return max(indexes) + 1 if indexes else 0


def _next_base_vm_index(user_db_id: int) -> int:
    """Return the next available base_vm_index for a user, computed from existing VM MACs in DB."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT v.mac_address
                FROM vms v
                JOIN deployments d ON v.deployment_id = d.id
                WHERE d.user_id = %s AND v.mac_address IS NOT NULL
                """,
                (user_db_id,),
            )
            macs = [r["mac_address"] for r in cur.fetchall()]
    return _next_base_from_macs(macs)


# ── Step 3: Scenario network VNets ────────────────────────────────────────────

def _create_scenario_networks(
    deployment_id: int,
    user_id: int,
    networks: list[NetworkSpec],
    proxmox: ProxmoxClient,
    log_fn: Callable[[str], None] = print,
) -> None:
    """Create a Proxmox SDN VNet in labzone for each network in the scenario.

    Uses a two-phase DB insert so the VNet name (which embeds the DB row ID) can be
    computed before hitting the Proxmox API. Idempotent: skips VNets that already
    exist in both DB and Proxmox; auto-removes stale Proxmox VNets from DB resets.
    Calls apply_sdn() once after all creates.
    """
    sdn_changed = False

    for net_spec in networks:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, vnet FROM networks WHERE deployment_id=%s AND name=%s",
                    (deployment_id, net_spec.name),
                )
                row = cur.fetchone()

        if row and row["vnet"]:
            vnet_name = row["vnet"]
            net_id = row["id"]
            if proxmox.vnet_exists(vnet_name):
                log_fn(f"VNet {vnet_name} already exists (network: {net_spec.name}), skipping")
                continue
            # In DB but missing from Proxmox (e.g. Proxmox restored) — fall through to recreate
        else:
            if row:
                # INSERT happened in a previous partial run but UPDATE did not
                net_id = row["id"]
            else:
                # Phase 1: insert placeholder so we get the DB-assigned ID
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO networks (deployment_id, name, vnet) VALUES (%s, %s, NULL) RETURNING id",
                            (deployment_id, net_spec.name),
                        )
                        net_id = cur.fetchone()["id"]

            # Phase 2: compute deterministic name and store it
            vnet_name = f"v{user_id:02x}{net_id:05x}"
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE networks SET vnet=%s WHERE id=%s", (vnet_name, net_id))

            # Pre-flight: same name exists in Proxmox but not in our DB (stale from DB reset)
            if proxmox.vnet_exists(vnet_name):
                log_fn(f"removing stale VNet {vnet_name}")
                proxmox.delete_vnet(vnet_name)

        log_fn(f"creating SDN VNet {vnet_name} (network: {net_spec.name})")
        proxmox.create_vnet(vnet_name, "labzone", tag=net_id + 10000)
        sdn_changed = True

    if sdn_changed:
        proxmox.apply_sdn()


# ── Step 3b: Hot template pre-flight ─────────────────────────────────────────

def _link_hot_template(deployment_id: int, hot_template_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO deployment_hot_templates (deployment_id, hot_template_id) "
                "VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (deployment_id, hot_template_id),
            )


def _prepare_hot_templates(
    spec: ScenarioSpec,
    user_db_id: int,
    proxmox: ProxmoxClient,
    storage: str,
    nodes: list,
    template_vmids: dict[str, int],
    deployment_id: int,
    log_fn: Callable[[str], None],
) -> dict[str, int]:
    """Ensure hot templates exist for all clone_mode=linked VM specs.

    For each unique template with clone_mode=linked:
      - Reuses existing hot template if present in DB and Proxmox (increments ref_count).
      - Creates a new hot template via full clone from NFS → fast storage, then converts
        to Proxmox template for CoW cloning.

    Returns mapping: template name → hot template VMID.
    Requires shared storage (Ceph/RBD). On non-shared storage linked clones are not
    supported by Proxmox at the API level — returns {} so callers fall back to full clones.
    """
    linked_templates = sorted({
        vm.template for vm in spec.vms
        if vm.type == "vm" and vm.clone_mode == "linked"
    })
    if not linked_templates:
        return {}

    storage_list = proxmox.get_storage()
    storage_info = next((s for s in storage_list if s.name == storage), None)
    if not storage_info or not storage_info.shared:
        log_fn(
            f"[hot-template] storage '{storage}' does not support linked clones "
            f"— falling back to full clones"
        )
        return {}

    online_nodes = [n for n in nodes if n.status == "online"]
    if not online_nodes:
        raise RuntimeError("no online nodes available for hot template creation")
    target_node = online_nodes[0].name

    result: dict[str, int] = {}

    for template_name in linked_templates:
        nfs_vmid = template_vmids[template_name]

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, vmid FROM hot_templates "
                    "WHERE user_id=%s AND template=%s AND storage=%s",
                    (user_db_id, template_name, storage),
                )
                row = cur.fetchone()

        if row and row["vmid"] is not None:
            hot_id, hot_vmid = row["id"], row["vmid"]
            if proxmox.vm_exists(hot_vmid):
                log_fn(f"[hot-template] {template_name} already ready (VMID {hot_vmid}) — reusing")
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE hot_templates SET ref_count = ref_count + 1 WHERE id=%s",
                            (hot_id,),
                        )
                result[template_name] = hot_vmid
                _link_hot_template(deployment_id, hot_id)
                continue
            # Stale DB entry (hot template missing from Proxmox) — clean up and recreate
            log_fn(f"[hot-template] {template_name} stale entry (VMID {hot_vmid} not in Proxmox) — recreating")
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM hot_templates WHERE id=%s", (hot_id,))

        # Phase 1: reserve a row to get the auto-ID used for VMID computation
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO hot_templates (user_id, template, storage, ref_count) "
                    "VALUES (%s, %s, %s, 1) RETURNING id",
                    (user_db_id, template_name, storage),
                )
                hot_id = cur.fetchone()["id"]

        hot_vmid = ids.HOT_TEMPLATE_VMID_BASE + hot_id
        hot_name = f"hot-{template_name.replace('/', '-')}"

        log_fn(f"[hot-template] copying {template_name} (NFS VMID {nfs_vmid}) → VMID {hot_vmid} on {storage}")
        proxmox.create_vm(
            node=target_node,
            vmid=hot_vmid,
            template_vmid=nfs_vmid,
            name=hot_name,
            cpus=1,
            memory=512,
            storage=storage,
            full=True,
        )
        proxmox.convert_to_template(target_node, hot_vmid)
        log_fn(f"[hot-template] {template_name} ready as Proxmox template (VMID {hot_vmid})")

        # Phase 2: persist the VMID now that Proxmox creation succeeded
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE hot_templates SET vmid=%s WHERE id=%s",
                    (hot_vmid, hot_id),
                )

        result[template_name] = hot_vmid
        _link_hot_template(deployment_id, hot_id)

    return result


# ── Step 4: VM creation ───────────────────────────────────────────────────────

def _create_vm(
    deployment_id: int,
    user_id: int,
    vm_spec: VMSpec,
    vm_index: int,
    template_vmid: int,
    vnet_map: dict[str, str],
    proxmox: ProxmoxClient,
    storage: str,
    node: str,
    log_fn: Callable[[str], None] = print,
    full: bool = True,
    skip_dnsmasq: bool = False,
) -> str:
    """Clone a template and wire all NICs for one scenario VM.

    Management NIC is always net0 with a deterministic MAC and a DHCP reservation.
    Scenario NICs start at net1 in the order declared in vm_spec.interfaces.
    Idempotent: if the VMID already exists in Proxmox, logs and returns without changes.
    Does not start the VM.
    """
    vmid_val = ids.vmid(user_id, vm_index)
    mgmt_mac_addr = ids.mac(user_id, vm_index, 0)
    mgmt_ip_addr = ids.mgmt_ip(user_id, vm_index)
    mgmt_vnet = f"mgmt{user_id}"

    # Build NIC list: mgmt first, then scenario interfaces in declaration order.
    nics: list[tuple] = [("net0", "eth0", "mgmt", mgmt_vnet, mgmt_mac_addr, mgmt_ip_addr)]
    vnet_ifaces = [iface for iface in vm_spec.interfaces if iface.type == "vnet"]
    for i, iface in enumerate(vnet_ifaces):
        slot = f"net{i + 1}"
        vnet_name = vnet_map[iface.network]
        iface_mac = ids.mac(user_id, vm_index, i + 1)
        nics.append((slot, iface.name, iface.network, vnet_name, iface_mac, None))

    if proxmox.vm_exists(vmid_val):
        node = proxmox.find_vm_node(vmid_val)
        log_fn(f"VM {vmid_val} ({vm_spec.name}) already exists on {node}, re-registering in DB")
        # Adopting an existing VMID assumes it was built from this same spec. Report
        # anything that contradicts that rather than starting a guest that silently
        # differs from the scenario — a half-created VM boots in ways that are hard
        # to trace back to here.
        try:
            existing = proxmox.get_vm_config(node, vmid_val)
            drift = []
            if len([k for k in existing if re.fullmatch(r"net\d+", k)]) != len(nics):
                drift.append(f"has {len([k for k in existing if re.fullmatch(r'net.', k)])} NIC(s), scenario declares {len(nics)}")
            for field in ("bios", "machine", "ostype"):
                want = getattr(vm_spec, field)
                if want and existing.get(field) != want:
                    drift.append(f"{field}={existing.get(field) or 'unset'}, scenario wants {want}")
            if vm_spec.efidisk and "efidisk0" not in existing:
                drift.append("no efidisk0, scenario wants one")
            if drift:
                log_fn(f"warning: VM {vmid_val} does not match the scenario — " + "; ".join(drift))
                log_fn(f"warning: it was likely left behind by a failed run; "
                       f"destroy it and redeploy to rebuild it correctly")
        except Exception as exc:
            log_fn(f"warning: could not verify existing VM {vmid_val} against the scenario: {exc}")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vms
                        (deployment_id, name, vmid, node, image, cpus, memory_mb, mac_address, management_ip)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (deployment_id, vm_spec.name, vmid_val, node, vm_spec.template,
                     vm_spec.cpus, vm_spec.memory, mgmt_mac_addr, mgmt_ip_addr),
                )
                cur.executemany(
                    """
                    INSERT INTO vm_nics (vmid, slot, iface_name, network, vnet, mac, ip)
                    VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
                    """,
                    [(vmid_val, *nic) for nic in nics],
                )
        return node

    log_fn(f"cloning template {template_vmid} → VMID {vmid_val} ({vm_spec.name}) on {node}")
    proxmox.create_vm(node, vmid_val, template_vmid, vm_spec.name, vm_spec.cpus, vm_spec.memory, storage, full=full, qemu_agent=vm_spec.qemu_agent, cpu_type=vm_spec.cpu_type,
                      bios=vm_spec.bios, machine=vm_spec.machine, ostype=vm_spec.ostype,
                      efidisk=vm_spec.efidisk, tpm=vm_spec.tpm, vga=vm_spec.vga,
                      serial=vm_spec.console == "serial")

    # Optional per-VM NIC model (e.g. e1000 for IOSvL2); default virtio.
    nic_model = vm_spec.nic_model or "virtio"
    log_fn(f"  net0: MAC={mgmt_mac_addr} bridge={mgmt_vnet} IP={mgmt_ip_addr} model={nic_model}")
    proxmox.add_nic(node, vmid_val, "net0", mgmt_vnet, mgmt_mac_addr, model=nic_model)
    if not skip_dnsmasq:
        dnsmasq.add_dhcp_host(user_id, mgmt_mac_addr, mgmt_ip_addr)

    for slot, iface_name, network, vnet_name, iface_mac, _ in nics[1:]:
        log_fn(f"  {slot}: network={network} vnet={vnet_name} MAC={iface_mac} model={nic_model}")
        proxmox.add_nic(node, vmid_val, slot, vnet_name, iface_mac, model=nic_model)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO vms
                    (deployment_id, name, vmid, node, image, cpus, memory_mb, mac_address, management_ip)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (deployment_id, vm_spec.name, vmid_val, node, vm_spec.template,
                 vm_spec.cpus, vm_spec.memory, mgmt_mac_addr, mgmt_ip_addr),
            )
            cur.executemany(
                """
                INSERT INTO vm_nics (vmid, slot, iface_name, network, vnet, mac, ip)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                [(vmid_val, *nic) for nic in nics],
            )
    return node


# ── Step 3b: Container create ─────────────────────────────────────────────────


def _create_ct(
    deployment_id: int,
    user_id: int,
    vm_spec,
    vm_index: int,
    ct_template_volid: str,
    vnet_map: dict[str, str],
    proxmox: ProxmoxClient,
    storage: str,
    node: str,
    log_fn: Callable[[str], None] = print,
    skip_dnsmasq: bool = False,
) -> str:
    """Create an LXC container and register it in the DB.

    Management NIC is always net0 with a deterministic MAC and a DHCP reservation.
    Scenario NICs start at net1. All NICs are passed at create time (pct create).
    """
    vmid_val = ids.vmid(user_id, vm_index)
    mgmt_mac_addr = ids.mac(user_id, vm_index, 0)
    mgmt_ip_addr = ids.mgmt_ip(user_id, vm_index)
    mgmt_vnet = f"mgmt{user_id}"

    nics: list[tuple] = [("net0", "eth0", "mgmt", mgmt_vnet, mgmt_mac_addr, mgmt_ip_addr)]
    vnet_ifaces = [iface for iface in vm_spec.interfaces if iface.type == "vnet"]
    for i, iface in enumerate(vnet_ifaces):
        slot = f"net{i + 1}"
        vnet_name = vnet_map[iface.network]
        iface_mac = ids.mac(user_id, vm_index, i + 1)
        nics.append((slot, iface.name, iface.network, vnet_name, iface_mac, None))

    if proxmox.ct_exists(vmid_val):
        node = proxmox.find_ct_node(vmid_val)
        log_fn(f"CT {vmid_val} ({vm_spec.name}) already exists on {node}, re-registering in DB")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vms
                        (deployment_id, name, vmid, node, image, cpus, memory_mb,
                         mac_address, management_ip, type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'container')
                    ON CONFLICT DO NOTHING
                    """,
                    (deployment_id, vm_spec.name, vmid_val, node, vm_spec.template,
                     vm_spec.cpus, vm_spec.memory, mgmt_mac_addr, mgmt_ip_addr),
                )
                cur.executemany(
                    """
                    INSERT INTO vm_nics (vmid, slot, iface_name, network, vnet, mac, ip)
                    VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
                    """,
                    [(vmid_val, *nic) for nic in nics],
                )
        return node

    log_fn(f"creating CT VMID {vmid_val} ({vm_spec.name}) on {node}")

    net_params: dict[str, str] = {}
    log_fn(f"  net0: MAC={mgmt_mac_addr} bridge={mgmt_vnet} IP={mgmt_ip_addr}")
    net_params["net0"] = f"name=eth0,bridge={mgmt_vnet},hwaddr={mgmt_mac_addr},ip=dhcp"
    if not skip_dnsmasq:
        dnsmasq.add_dhcp_host(user_id, mgmt_mac_addr, mgmt_ip_addr)

    for slot, iface_name, network, vnet_name, iface_mac, _ in nics[1:]:
        log_fn(f"  {slot}: network={network} vnet={vnet_name} MAC={iface_mac}")
        net_params[slot] = f"name={iface_name},bridge={vnet_name},hwaddr={iface_mac}"

    proxmox.create_ct(
        node, vmid_val, ct_template_volid, vm_spec.name,
        vm_spec.cpus, vm_spec.memory, storage, net_params,
        disk_gb=vm_spec.disk_gb,
    )

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO vms
                    (deployment_id, name, vmid, node, image, cpus, memory_mb,
                     mac_address, management_ip, type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'container')
                """,
                (deployment_id, vm_spec.name, vmid_val, node, vm_spec.template,
                 vm_spec.cpus, vm_spec.memory, mgmt_mac_addr, mgmt_ip_addr),
            )
            cur.executemany(
                """
                INSERT INTO vm_nics (vmid, slot, iface_name, network, vnet, mac, ip)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                [(vmid_val, *nic) for nic in nics],
            )
    return node


# ── Cancellation ──────────────────────────────────────────────────────────────

class DeploymentCancelled(Exception):
    pass


def _check_cancelled(deployment_id: int) -> None:
    """Raise DeploymentCancelled if the deployment has been destroyed externally."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM deployments WHERE id=%s", (deployment_id,))
            row = cur.fetchone()
    if row and row["status"] == "destroyed":
        raise DeploymentCancelled("deployment was destroyed — aborting")


# ── Step 5: VM start and SSH readiness ────────────────────────────────────────

def _wait_for_ssh(
    ip: str,
    vmid: int,
    timeout: int = 300,
    interval: int = 5,
    deployment_id: int | None = None,
) -> None:
    """Poll port 22 until sshd sends its SSH banner, then return.

    A TCP connection alone is not sufficient — sshd may accept the socket
    before it is ready to handle the SSH handshake. Reading the banner
    (b"SSH-...") confirms the daemon is fully initialised.

    Checks for external cancellation (deployment destroyed) on each poll cycle.
    Raises TimeoutError if the VM does not respond within timeout seconds.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if deployment_id is not None:
            _check_cancelled(deployment_id)
        try:
            with socket.create_connection((ip, 22), timeout=5) as sock:
                sock.settimeout(5)
                banner = sock.recv(256)
                if banner.startswith(b"SSH-"):
                    return
        except OSError:
            pass
        time.sleep(interval)
    raise TimeoutError(f"VM {vmid} at {ip} did not accept SSH within {timeout}s")


def _wait_for_ssh_password_auth(
    ip: str,
    vmid: int,
    user: str,
    password: str,
    timeout: int = 300,
    interval: int = 5,
    deployment_id: int | None = None,
) -> None:
    """Like _wait_for_ssh, but also confirms password authentication actually works.

    A freshly created container can answer the SSH banner (proving sshd is up)
    well before whatever activates its root password — first-boot scripts, PAM —
    has finished. OpenSSH/Ansible don't retry on auth failure (rightly, for real
    bad credentials), so a transient race here surfaces as a hard, immediate
    "Permission denied" rather than a timeout. Retrying an actual authenticated
    connection (not just the banner) closes that gap.

    Requires the `sshpass` binary. If it isn't installed, falls back to the
    banner-only check (the pre-existing behavior) rather than blocking the whole
    deployment over a missing optional tool — this check is a best-effort
    improvement, not a hard requirement.
    """
    _wait_for_ssh(ip, vmid, timeout=timeout, deployment_id=deployment_id)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if deployment_id is not None:
            _check_cancelled(deployment_id)
        try:
            result = subprocess.run(
                ["sshpass", "-p", password, "ssh",
                 "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "ConnectTimeout=5",
                 f"{user}@{ip}", "true"],
                capture_output=True, timeout=10,
            )
        except FileNotFoundError:
            return
        if result.returncode == 0:
            return
        time.sleep(interval)
    raise TimeoutError(f"SSH password auth to {ip} (VMID {vmid}) did not succeed within {timeout}s")


# How long the guest must read clean, continuously and without rebooting, before
# it counts as settled. A count of polls is the wrong unit — two reads ten seconds
# apart says nothing about a reboot a minute later. Measured first boot: WinRM
# opened 312s after power-on and the guest stayed busy for a further 56s, so this
# needs to comfortably outlast that tail.
_WINRM_SETTLE_SECONDS = 90

# Upper bound on "boot, then finish first boot" for a Windows guest.
_WINRM_FIRST_BOOT_TIMEOUT = 1800

# Measured on a real first boot of a Windows 11 Vagrant box: at the moment WinRM
# starts accepting connections, every registry marker below already reads clean
# (SystemSetupInProgress=0, GeneralizationState=7, CleanupState=2, no reboot
# flags) while the guest is still on the "This might take a few minutes" screen
# and about to reboot itself. The running-process and servicing checks are the
# ones that actually catch that window; the registry markers are kept because
# they catch the *other* cases (a pending servicing reboot, an interrupted
# sysprep) that the process checks do not.
_WINRM_READY_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$reasons = @()
$setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
if ($setup -and $setup.SystemSetupInProgress -ne 0) { $reasons += 'setup in progress' }
if ($setup -and $setup.OOBEInProgress -ne 0) { $reasons += 'OOBE in progress' }
$ss = Get-ItemProperty 'HKLM:\SYSTEM\Setup\Status\SysprepStatus'
if ($ss.GeneralizationState -ne $null -and $ss.GeneralizationState -ne 7) {
    $reasons += "sysprep generalization state $($ss.GeneralizationState)" }
if ($ss.CleanupState -ne $null -and $ss.CleanupState -ne 2) {
    $reasons += "sysprep cleanup state $($ss.CleanupState)" }
# Reported with a REBOOT: prefix so the caller can act on it. These flags never
# clear by themselves — a freshly built image can ship with servicing already
# pending — so blocking on them would burn the entire timeout.
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    $reasons += 'REBOOT:servicing reboot pending' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
    $reasons += 'REBOOT:update reboot pending' }
$procs = @(Get-Process msoobe,oobeldr,sysprep,FirstLogonAnim -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name -Unique)
# setup.exe is matched by path, not name: plenty of third-party installers are
# called setup.exe and some linger for minutes. Edge WebView's updater
# ("...\EdgeWebView\...\Installer\setup.exe --msedgewebview") held this gate open
# until it timed out on an otherwise idle guest.
if (Get-CimInstance Win32_Process -Filter "Name='setup.exe'" |
    Where-Object { $_.ExecutablePath -like 'C:\Windows\*' -or $_.ExecutablePath -like 'C:\$WINDOWS.~BT\*' }) {
    $procs += 'setup (Windows)'
}
if ($procs) { $reasons += "first-boot process running: $($procs -join ',')" }
if ((Get-Service TrustedInstaller).Status -eq 'Running') { $reasons += 'servicing (TrustedInstaller) active' }
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
if ($reasons) { "NOTREADY|$boot|" + ($reasons -join '; ') } else { "READY|$boot|" }
"""


def _winrm_first_boot_state(ip: str, port: int, user: str, password: str) -> tuple[str, str, str]:
    """Return (state, boot_time, detail) for a Windows guest.

    state is READY, NOTREADY, or UNKNOWN. UNKNOWN means the check itself could not
    run — missing pywinrm, bad credentials, a WinRM hiccup — and callers treat it
    as "carry on", so this can only ever delay a deploy, never block one outright.
    """
    try:
        import winrm  # noqa: PLC0415 — optional at import time, only Windows guests need it
    except ImportError:
        return "UNKNOWN", "", "pywinrm not installed"
    try:
        session = winrm.Session(
            f"http://{ip}:{port}/wsman", auth=(user, password), transport="basic"
        )
        result = session.run_ps(_WINRM_READY_PS)
        if result.status_code != 0:
            return "UNKNOWN", "", "readiness script failed"
        parts = result.std_out.decode(errors="replace").strip().split("|")
        if len(parts) < 2:
            return "UNKNOWN", "", "unparseable readiness output"
        return parts[0], parts[1], (parts[2] if len(parts) > 2 else "")
    except Exception as exc:
        return "UNKNOWN", "", f"{type(exc).__name__}: {exc}"


def _winrm_reboot(ip: str, port: int, user: str, password: str) -> None:
    """Reboot a Windows guest over WinRM, best effort.

    The connection drops as the command runs, so an exception here is the normal
    outcome rather than a failure.
    """
    try:
        import winrm  # noqa: PLC0415
        winrm.Session(f"http://{ip}:{port}/wsman", auth=(user, password),
                      transport="basic", read_timeout_sec=30,
                      operation_timeout_sec=20).run_ps("shutdown /r /t 0 /f")
    except Exception:
        pass


def _wait_for_winrm(
    ip: str,
    vmid: int,
    port: int = 5985,
    timeout: int = 900,
    interval: int = 10,
    deployment_id: int | None = None,
    user: str = "",
    password: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> None:
    """Poll the WinRM port until the WSMan endpoint answers, then return.

    An open socket is not enough: Windows starts the listener well before WinRM
    can serve requests. An unauthenticated POST to /wsman is the cheapest proof
    the service is live — it answers 401 (or 405) once ready, and refuses the
    connection or hangs before that.

    The default timeout is deliberately longer than the SSH equivalent: a Windows
    first boot runs sysprep and a reboot cycle before WinRM comes up.
    """
    deadline = time.monotonic() + timeout
    url = f"http://{ip}:{port}/wsman"
    listening = False
    while not listening and time.monotonic() < deadline:
        if deployment_id is not None:
            _check_cancelled(deployment_id)
        try:
            # Any HTTP status back — 401 unauthenticated, 405 bad verb — proves WSMan
            # is serving. Only a transport-level failure means "not ready yet".
            httpx.post(url, content=b"", timeout=10)
            listening = True
        except httpx.HTTPError:
            time.sleep(interval)
    if not listening:
        raise TimeoutError(f"VM {vmid} at {ip} did not answer WinRM on port {port} within {timeout}s")

    if not password:
        return

    # WinRM answers well before Windows has finished first boot. Provisioning into
    # that window races the guest's own reboot, so hold until the state reads clean
    # continuously for _WINRM_SETTLE_SECONDS with no reboot in between. Any dirty
    # read, or a change in boot time, restarts the clock.
    stable_since: float | None = None
    last_boot = ""
    reported = ""
    ever_answered = False
    rebooted_for_pending = False
    while time.monotonic() < deadline:
        if deployment_id is not None:
            _check_cancelled(deployment_id)
        state, boot, detail = _winrm_first_boot_state(ip, port, user, password)
        now = time.monotonic()
        if state == "UNKNOWN":
            # Only proceed when the check was never usable at all (no pywinrm, bad
            # credentials). Once it has answered, losing it means the guest went
            # away mid-reboot — the worst possible moment to release Ansible.
            if ever_answered:
                stable_since = None
                if log_fn and reported != "guest unreachable":
                    log_fn("  waiting for Windows first boot to finish: guest unreachable (rebooting?)")
                    reported = "guest unreachable"
                time.sleep(interval)
                continue
            if log_fn:
                log_fn(f"  first-boot check unavailable ({detail}) — proceeding")
            return
        ever_answered = True

        # A pending servicing reboot never clears on its own. Trigger it once,
        # then keep waiting for the guest to come back and settle.
        if state != "READY" and all(r.startswith("REBOOT:") for r in detail.split("; ") if r):
            if not rebooted_for_pending:
                rebooted_for_pending = True
                if log_fn:
                    log_fn(f"  {detail.replace('REBOOT:', '')} — rebooting the guest to clear it")
                _winrm_reboot(ip, port, user, password)
                stable_since = None
                last_boot = ""
                time.sleep(interval)
                continue
        detail = detail.replace("REBOOT:", "")
        if state != "READY":
            stable_since = None
            if log_fn and detail and detail != reported:
                log_fn(f"  waiting for Windows first boot to finish: {detail}")
                reported = detail
        elif stable_since is not None and boot == last_boot:
            if now - stable_since >= _WINRM_SETTLE_SECONDS:
                if log_fn:
                    log_fn(f"  Windows settled (clean for {_WINRM_SETTLE_SECONDS}s)")
                return
        else:
            # First clean read, or the guest rebooted since the last one.
            if log_fn and last_boot and boot != last_boot:
                log_fn("  waiting for Windows first boot to finish: guest rebooted")
                reported = "guest rebooted"
            elif log_fn:
                # Say so explicitly: without this the countdown is silent, and a
                # deliberate quiet period is indistinguishable from a hang.
                log_fn(f"  Windows looks idle — holding {_WINRM_SETTLE_SECONDS}s to confirm "
                       "it does not reboot again")
            stable_since = now
        last_boot = boot
        time.sleep(interval)
    raise TimeoutError(
        f"VM {vmid} at {ip} answered WinRM but never finished first boot within {timeout}s"
    )


def _wait_for_ssh_ready(
    ip: str,
    vmid: int,
    connection: dict,
    timeout: int,
    deployment_id: int | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> None:
    """Wait for the VM's management transport to accept connections.

    Dispatches on connection type: winrm guests have no sshd, so probing port 22
    would burn the whole timeout and fail every Windows VM. network_cli and
    key-based auth get the banner-only check, where a password probe doesn't apply.
    """
    user = connection.get("user", "")
    password = connection.get("password", "")
    conn_type = connection.get("type", "ssh")
    if conn_type == "winrm":
        _wait_for_winrm(
            ip, vmid,
            port=int(connection.get("winrm_port", 5985)),
            # Floor, not the scenario's SSH timeout: a Windows first boot measured
            # ~5 min to open WinRM and several more minutes of on-and-off servicing
            # (FirstLogonAnim, then setup.exe, with TrustedInstaller cycling
            # throughout) before it stays quiet. 900s left no margin for that.
            timeout=max(timeout, _WINRM_FIRST_BOOT_TIMEOUT),
            deployment_id=deployment_id,
            user=user,
            password=password,
            log_fn=log_fn,
        )
    elif conn_type == "ssh" and password:
        _wait_for_ssh_password_auth(ip, vmid, user, password, timeout=timeout, deployment_id=deployment_id)
    else:
        _wait_for_ssh(ip, vmid, timeout=timeout, deployment_id=deployment_id)


# ── Step 6: Ansible provisioning ─────────────────────────────────────────────

def _find_ansible_bin() -> str:
    """Return the ansible-playbook binary path, preferring the active venv."""
    venv_bin = Path(sys.executable).parent
    candidate = venv_bin / "ansible-playbook"
    if candidate.is_file():
        return str(candidate)
    found = shutil.which("ansible-playbook")
    if found:
        return found
    raise RuntimeError("ansible-playbook not found in PATH")


def _substitute_user_id(obj, user_id: int):
    """Recursively replace {USER_ID} in strings within nested dicts/lists."""
    if isinstance(obj, str):
        return obj.replace("{USER_ID}", str(user_id))
    if isinstance(obj, dict):
        return {k: _substitute_user_id(v, user_id) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_user_id(item, user_id) for item in obj]
    return obj


def _substitute_vars(obj, subs: dict):
    """Recursively replace {{ key }} placeholders in strings using subs dict."""
    if isinstance(obj, str):
        for key, value in subs.items():
            obj = obj.replace("{{ " + key + " }}", value)
        return obj
    if isinstance(obj, dict):
        return {k: _substitute_vars(v, subs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_vars(item, subs) for item in obj]
    return obj


def _generate_vm_playbook(
    vm_name: str,
    ansible_section: dict,
    user_id: int,
    output_dir: Path,
    vm_ip: str | None = None,
    other_vms: list[tuple[str, str]] = (),
    run_phase: str = "provision",
    extra_vars: dict | None = None,
) -> Path:
    """Generate a per-VM Ansible playbook from the scenario's ansible block.

    Each task entry like {"task": "vyos/set_hostname", "vars": {...}} becomes an
    include_tasks block pointing at the absolute path of the role task file.
    {USER_ID} in vars is substituted with user_id; {{ vm_mgmt_ip }} with vm_ip.
    other_vms injects {name_underscored}_ip play vars for every other deployed VM.

    run_phase splits the task list by the optional per-task `phase:` marker:
    "provision" (deploy) keeps tasks WITHOUT `phase: detonate`; "detonate"
    (`lab detonate`) keeps ONLY those with it. extra_vars are merged last into
    play vars (e.g. the `art_tactic` filter for a detonation run).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    playbook_path = output_dir / f"playbook_{vm_name}.yml"

    tasks = []
    for entry in ansible_section.get("tasks") or []:
        is_detonate = entry.get("phase") == "detonate"
        if run_phase == "provision" and is_detonate:
            continue
        if run_phase == "detonate" and not is_detonate:
            continue
        task_ref = entry["task"]  # e.g. "vyos/set_hostname"
        role, task_name = task_ref.split("/", 1)
        task_file = _ROLES_DIR / role / "tasks" / f"{task_name}.yml"

        task_vars = _substitute_user_id(entry.get("vars", {}), user_id)
        if vm_ip:
            task_vars = _substitute_vars(task_vars, {
                "vm_mgmt_ip": vm_ip,
                "vm_mgmt_netmask": "255.255.0.0",
            })

        block: dict = {"name": task_ref, "include_tasks": str(task_file)}
        if task_vars:
            block["vars"] = task_vars
        tasks.append(block)

    play_vars = {
        "lab_ansible_dir": str(_ANSIBLE_DIR),
        "gateway_ip": ids.gateway_ip(user_id),
        "mgmt_timezone": _local_timezone(),
    }
    for name, ip in other_vms:
        play_vars[f"{name.replace('-', '_')}_ip"] = ip
    play_vars.update(ansible_section.get("vars", {}))
    if extra_vars:
        play_vars.update(extra_vars)

    play = {
        "name": f"Provision {vm_name}",
        "hosts": vm_name,
        "gather_facts": ansible_section.get("gather_facts", False),
        "become": ansible_section.get("become", False),
        "vars": play_vars,
        "tasks": tasks,
    }
    playbook_path.write_text(yaml.dump([play], default_flow_style=False, sort_keys=False))
    return playbook_path


def _local_timezone() -> str:
    """This host's IANA timezone (e.g. 'Europe/Warsaw'), or '' if undetermined.

    Exposed to plays as mgmt_timezone so guests can be set to the same wall clock
    as the management VM. /etc/localtime is a symlink into the zoneinfo tree on
    Debian; timedatectl is the fallback for hosts where it is a plain copy.
    """
    try:
        target = Path("/etc/localtime").resolve()
        parts = target.parts
        if "zoneinfo" in parts:
            return "/".join(parts[parts.index("zoneinfo") + 1:])
    except OSError:
        pass
    try:
        out = subprocess.run(["timedatectl", "show", "-p", "Timezone", "--value"],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _build_inventory(vm_name: str, mgmt_ip: str, conn: dict) -> str:
    """Build a single-host INI inventory string from a connection config dict."""
    conn_type = conn.get("type", "ssh")
    user = conn.get("user", "")
    password = conn.get("password", "")
    host_vars = f"ansible_host={mgmt_ip} ansible_user={user} ansible_password={password} vm_name={vm_name} management_ip={mgmt_ip}"

    if conn_type == "winrm":
        scheme = conn.get("winrm_scheme", "http")
        port = conn.get("winrm_port", 5985)
        transport = conn.get("winrm_transport", "basic")
        # pywinrm defaults (20s op / 30s read) are too tight: a slow choco install
        # (e.g. googlechrome pulling its MSI) can make a single WSMan Receive take
        # >30s under load -> read timeout -> the host is marked UNREACHABLE, which
        # ansible does NOT apply until/retries to. Give it real headroom; read must
        # stay > operation. Overridable per scenario via winrm_operation/read_timeout.
        op_timeout = conn.get("winrm_operation_timeout", 120)
        read_timeout = conn.get("winrm_read_timeout", 150)
        host_vars += (
            f" ansible_connection=winrm"
            f" ansible_winrm_scheme={scheme}"
            f" ansible_port={port}"
            f" ansible_winrm_transport={transport}"
            f" ansible_winrm_server_cert_validation=ignore"
            f" ansible_winrm_operation_timeout_sec={op_timeout}"
            f" ansible_winrm_read_timeout_sec={read_timeout}"
        )
    elif conn_type in ("network_cli", "httpapi"):
        network_os = conn.get("network_os", "")
        host_vars += (
            f" ansible_network_os={network_os}"
            f" ansible_connection={conn_type}"
        )
        # Cisco IOS/IOSvL2 speak only legacy SSH crypto (SHA1 KEX/MAC, ssh-rsa host
        # keys, CBC ciphers) that modern paramiko can't negotiate. Use libssh
        # (ansible-pylibssh) pointed at our legacy-crypto ssh config so it can.
        if network_os in ("ios", "iosxr"):
            host_vars += (
                f" ansible_network_cli_ssh_type=libssh"
                f" ansible_libssh_config_file={_ANSIBLE_DIR}/files/cisco-legacy-ssh.config"
            )

    return f"[all]\n{vm_name} {host_vars}\n"


def _provision_vm(
    vm_name: str,
    mgmt_ip: str,
    vm_spec: VMSpec,
    user_id: int,
    log_fn: Callable[[str], None] = print,
    other_vms: list[tuple[str, str]] = (),
    run_phase: str = "provision",
    extra_vars: dict | None = None,
) -> bool:
    """Generate a per-VM playbook and run ansible-playbook against it.

    Returns True on success, False on failure. Provisioning failure is logged
    but not fatal — the deployment stays up. Skips if vm_spec.ansible is empty.

    run_phase / extra_vars are passed through to _generate_vm_playbook: deploy
    runs the "provision" phase, `lab detonate` the "detonate" phase.
    """
    if not vm_spec.ansible:
        log_fn(f"{vm_name}: no ansible config — skipping")
        return True

    conn = vm_spec.ansible.get("connection", {})
    inventory = _build_inventory(vm_name, mgmt_ip, conn)

    tmpdir = tempfile.mkdtemp()
    try:
        inv_path = os.path.join(tmpdir, "inventory.ini")
        with open(inv_path, "w") as f:
            f.write(inventory)
        os.chmod(inv_path, 0o600)

        playbook_path = _generate_vm_playbook(vm_name, vm_spec.ansible, user_id, Path(tmpdir), vm_ip=mgmt_ip, other_vms=other_vms, run_phase=run_phase, extra_vars=extra_vars)

        subprocess.run(["ssh-keygen", "-R", mgmt_ip], capture_output=True)

        ansible_bin = _find_ansible_bin()
        env = dict(os.environ)
        env["ANSIBLE_CONFIG"] = str(_ANSIBLE_DIR / "ansible.cfg")
        env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
        env["ANSIBLE_RETRY_FILES_ENABLED"] = "False"
        env["ANSIBLE_COLLECTIONS_PATH"] = str(_ANSIBLE_DIR / "collections")
        env["ANSIBLE_ROLES_PATH"] = str(_ROLES_DIR)
        # Unbuffered stdout so ansible task/item results stream to the op log live
        # (e.g. per-package during a chocolatey loop) instead of arriving in one
        # chunk when the play ends.
        env["PYTHONUNBUFFERED"] = "1"

        cmd = [ansible_bin, str(playbook_path), "-i", inv_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        for line in iter(proc.stdout.readline, ""):
            log_fn(line.rstrip())
        proc.wait()
        return proc.returncode == 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _provision_replica_group(
    base_name: str,
    group_specs: list[VMSpec],
    group_ips: list[str],
    ansible_section: dict,
    other_vms: list[tuple[str, str]],
    user_id: int,
    log_fn: Callable[[str], None] = print,
) -> bool:
    """Generate a batch inventory + playbook and run one ansible-playbook for a replica group.

    Builds an INI inventory with per-host vars (vm_name, vm_index, management_ip) and
    group vars (connection settings, other-VM IPs, task vars). All N replicas are targeted
    in a single ansible-playbook run; Ansible handles parallelism via forks.

    Returns True on success, False on failure. Skips if ansible_section is empty.
    """
    if not ansible_section:
        log_fn(f"[{base_name}] no ansible config — skipping")
        return True

    conn = ansible_section.get("connection", {})
    ansible_user = conn.get("user", "")
    ansible_password = conn.get("password", "")

    # Ansible group name: must be a valid identifier (no dashes)
    group_id = base_name.replace("-", "_")

    # Per-host lines: IP + inline host vars
    host_lines = [
        f"{ip}  vm_name={spec.name}  vm_index={spec.replica_index}  management_ip={ip}"
        for spec, ip in zip(group_specs, group_ips)
    ]

    # Group vars: connection + other-VM IPs only
    group_var_pairs: list[str] = [
        f"ansible_user={ansible_user}",
        f"ansible_password={ansible_password}",
        "ansible_ssh_common_args='-o StrictHostKeyChecking=no'",
        f"gateway_ip={ids.gateway_ip(user_id)}",
    ]
    for vm_name, vm_ip in other_vms:
        group_var_pairs.append(f"{vm_name.replace('-', '_')}_ip={vm_ip}")

    inventory = (
        f"[{group_id}]\n"
        + "\n".join(host_lines)
        + f"\n\n[{group_id}:vars]\n"
        + "\n".join(group_var_pairs)
        + "\n"
    )

    # Playbook: one include_tasks per task entry; task-level vars as block vars
    # so they take precedence over play vars (same as standalone VM path).
    tasks = []
    for entry in ansible_section.get("tasks") or []:
        # Replica groups only ever run the provision phase; detonate-phase tasks
        # (if any) are handled by `lab detonate`, never during deploy.
        if entry.get("phase") == "detonate":
            continue
        task_ref = entry["task"]
        role, task_name = task_ref.split("/", 1)
        task_file = _ROLES_DIR / role / "tasks" / f"{task_name}.yml"
        task_vars = _substitute_user_id(entry.get("vars") or {}, user_id)
        block: dict = {"name": task_ref, "include_tasks": str(task_file)}
        if task_vars:
            block["vars"] = task_vars
        tasks.append(block)

    play_vars: dict = {"lab_ansible_dir": str(_ANSIBLE_DIR)}
    play_vars.update(ansible_section.get("vars") or {})

    play = {
        "name": f"Provision {base_name} replicas",
        "hosts": group_id,
        "become": True,
        "gather_facts": ansible_section.get("gather_facts", False),
        "vars": play_vars,
        "tasks": tasks,
    }

    tmpdir = tempfile.mkdtemp()
    try:
        inv_path = os.path.join(tmpdir, "inventory.ini")
        with open(inv_path, "w") as f:
            f.write(inventory)
        os.chmod(inv_path, 0o600)

        playbook_path = Path(tmpdir) / "playbook.yml"
        playbook_path.write_text(yaml.dump([play], default_flow_style=False, sort_keys=False))

        for ip in group_ips:
            subprocess.run(["ssh-keygen", "-R", ip], capture_output=True)

        ansible_bin = _find_ansible_bin()
        env = dict(os.environ)
        env["ANSIBLE_CONFIG"] = str(_ANSIBLE_DIR / "ansible.cfg")
        env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
        env["ANSIBLE_RETRY_FILES_ENABLED"] = "False"
        env["ANSIBLE_COLLECTIONS_PATH"] = str(_ANSIBLE_DIR / "collections")
        env["ANSIBLE_ROLES_PATH"] = str(_ROLES_DIR)
        # Unbuffered stdout so task/item results stream to the op log live.
        env["PYTHONUNBUFFERED"] = "1"

        log_fn(f"[{base_name}] running ansible-playbook for {len(group_specs)} replicas")
        cmd = [ansible_bin, str(playbook_path), "-i", inv_path]
        _forks = ansible_section.get("forks")
        if _forks:
            cmd += ["--forks", str(_forks)]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env
        )
        for line in iter(proc.stdout.readline, ""):
            log_fn(line.rstrip())
        proc.wait()
        return proc.returncode == 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── Step 7: DeployEngine orchestrator ────────────────────────────────────────

def _get_user(username: str) -> dict:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, user_id FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
    if not row:
        raise RuntimeError(f"user '{username}' not found — create the user first")
    return row


def _load_deployment_ops(deployment_name: str, username: str):
    """Shared setup for the snapshot / art-run operations.

    Returns (user_id, deployment_id, spec, rows) where rows maps VM name → its DB
    row (vmid/node/management_ip/type/status). The scenario is RE-PARSED from disk
    (scenarios/<deployment_name>/scenario.yml) so edits to atomic_tests/tactics are
    picked up between runs.
    """
    user = _get_user(username)
    user_db_id: int = user["id"]
    user_id: int = user["user_id"]

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM deployments WHERE user_id=%s AND name=%s AND status != 'destroyed'"
                " ORDER BY created_at DESC LIMIT 1",
                (user_db_id, deployment_name),
            )
            dep_row = cur.fetchone()
    if not dep_row:
        raise RuntimeError(f"deployment '{deployment_name}' not found for user '{username}'")
    deployment_id: int = dep_row["id"]

    scenario_file = _SCENARIOS_DIR / deployment_name / "scenario.yml"
    if not scenario_file.exists():
        raise RuntimeError(f"scenario file not found: {scenario_file}")
    spec = parse_scenario(scenario_file)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, vmid, node, management_ip, type, status FROM vms WHERE deployment_id=%s",
                (deployment_id,),
            )
            rows = {r["name"]: dict(r) for r in cur.fetchall()}

    return user_id, deployment_id, spec, rows


def _snapshot_targets(spec: ScenarioSpec, rows: dict, only_vm: str | None = None) -> list:
    """(VMSpec, row) pairs for VMs that declare `snapshot:` and exist in the deployment.
    only_vm narrows to a single VM name (raises if it isn't a snapshot VM)."""
    targets = []
    for vm in spec.vms:
        if not vm.snapshot:
            continue
        if only_vm and vm.name != only_vm:
            continue
        row = rows.get(vm.name)
        if not row or row.get("vmid") is None:
            continue
        targets.append((vm, row))
    if only_vm and not targets:
        raise RuntimeError(
            f"VM '{only_vm}' does not declare `snapshot:` in this scenario (or isn't deployed)"
        )
    return targets


def _dependency_order(spec: ScenarioSpec, names: set[str]) -> list[str]:
    """Names ordered by dependency waves (routers → core → elk → victim → …)."""
    ordered: list[str] = []
    for wave in execution_plan(spec):
        ordered.extend(n for n in wave if n in names)
    # Any names not in the plan (shouldn't happen) tacked on at the end.
    ordered.extend(n for n in names if n not in ordered)
    return ordered


def _get_existing_deployment(user_db_id: int, deployment_name: str) -> dict | None:
    """Return the non-destroyed deployment row (id, status) or None."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, status FROM deployments WHERE user_id=%s AND name=%s AND status != 'destroyed'"
                " ORDER BY created_at DESC LIMIT 1",
                (user_db_id, deployment_name),
            )
            return cur.fetchone()


def user_exists(username: str) -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username=%s", (username,))
            return cur.fetchone() is not None


def get_deployment_status(username: str, deployment_name: str) -> str | None:
    """Return current status of a deployment for a user, or None if not found/destroyed."""
    user = _get_user(username)
    row = _get_existing_deployment(user["id"], deployment_name)
    return row["status"] if row else None


def _create_deployment(
    user_db_id: int,
    deployment_name: str,
    base_vm_index: int,
    scenario_dict: dict | None = None,
) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO deployments (user_id, name, status, base_vm_index, scenario) "
                "VALUES (%s, %s, 'deploying', %s, %s::jsonb) RETURNING id",
                (
                    user_db_id,
                    deployment_name,
                    base_vm_index,
                    json.dumps(scenario_dict) if scenario_dict is not None else None,
                ),
            )
            return cur.fetchone()["id"]


def _update_deployment_scenario(deployment_id: int, scenario_dict: dict) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE deployments SET scenario=%s::jsonb WHERE id=%s",
                (json.dumps(scenario_dict), deployment_id),
            )


def _next_vm_index_for_deployment(deployment_id: int, user_id: int) -> int:
    """Return the next available vm_index for adding VMs to an existing deployment."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT vmid FROM vms WHERE deployment_id=%s AND vmid IS NOT NULL",
                (deployment_id,),
            )
            rows = cur.fetchall()
    if not rows:
        return 0
    return max(r["vmid"] - user_id * 100_000 for r in rows) + 1


def _inferred_base_idx_collides(
    base_idx: int,
    full_flat: dict[str, int],
    missing_names: list[str],
    claimed_vmids: set[int],
    user_id: int,
) -> bool:
    """Check whether an inferred partial-retry base_idx would reuse a VMID already
    claimed by some other VM in the deployment.

    The inference reproduces the *original* index layout from a surviving replica's
    real VMID — correct only if nothing else has since claimed that index range. Once
    other VMs (other replica batches, scale-out nodes, etc.) get created afterward and
    land in that same range, the inference goes stale and silently collides.
    """
    would_use_vmids = {user_id * 100_000 + base_idx + full_flat[name] for name in missing_names}
    return bool(would_use_vmids & claimed_vmids)


def _resolve_target(spec: ScenarioSpec, target_name: str) -> list[VMSpec]:
    """Return VMSpecs matching target_name: exact name, replica base, or comma-separated list."""
    names = [n.strip() for n in target_name.split(",") if n.strip()]
    if len(names) > 1:
        result: list[VMSpec] = []
        seen: set[str] = set()
        for name in names:
            for vm in _resolve_target(spec, name):
                if vm.name not in seen:
                    result.append(vm)
                    seen.add(vm.name)
        return result
    name = names[0] if names else target_name
    exact = [vm for vm in spec.vms if vm.name == name]
    if exact:
        if exact[0].replica_base:
            raise ValueError(
                f"'{name}' is a replica instance — "
                f"use the base name '{exact[0].replica_base}' to target the full group"
            )
        return exact
    group = [vm for vm in spec.vms if vm.replica_base == name]
    if group:
        return group
    raise ValueError(f"target '{name}' not found in scenario")


def _classify_target_vms(
    target_specs: list[VMSpec],
    already_deployed: set[str],
    deployed_info: dict[str, dict],
    deployment_name: str,
) -> tuple[list[VMSpec], list[VMSpec], list[VMSpec]]:
    """Split a --target batch into (missing, already_in_target, ansible_only).

    missing: no existing DB row — needs full creation.
    already_in_target: replica VMs that already exist *and* are fully
        provisioned (ansible_status success/running) — creation is skipped,
        kept around (by the caller) for index inference during a partial
        replica-group retry.
    ansible_only: VMs (replica or standalone) that already exist but never
        successfully ran Ansible (ansible_status 'skipped' — e.g. created via a
        prior --skip-ansible Step A — or 'failed', e.g. a batch that partially
        failed mid-provisioning) — needs Ansible only, never re-created. This
        applies to replicas too: a replica group that partially failed
        shouldn't require destroying and recreating the whole group just to
        retry provisioning on the ones that already exist.

    Raises RuntimeError if a non-replica target already exists with any other
    ansible_status (i.e. it's genuinely fully deployed already).
    """
    missing: list[VMSpec] = []
    already_in_target: list[VMSpec] = []
    ansible_only: list[VMSpec] = []
    for ts in target_specs:
        if ts.name in already_deployed:
            if deployed_info[ts.name]["ansible_status"] in ("skipped", "failed"):
                ansible_only.append(ts)
            elif ts.replica_base:
                already_in_target.append(ts)
            else:
                raise RuntimeError(
                    f"VM '{ts.name}' is already deployed in deployment '{deployment_name}'"
                )
        else:
            missing.append(ts)
    return missing, already_in_target, ansible_only


def _check_target_deps_fresh(target_specs: list[VMSpec], deployment_name: str) -> None:
    """Raise RuntimeError if any target spec has dependencies not satisfied within the batch."""
    batch_names = {ts.name for ts in target_specs}
    all_deps: set[str] = set()
    for ts in target_specs:
        all_deps.update(ts.depends_on)
    all_deps -= batch_names  # deps satisfied by other VMs in the same batch are fine
    if all_deps:
        first_dep = sorted(all_deps)[0]
        raise RuntimeError(
            f"cannot deploy — dependency '{first_dep}' is not deployed\n"
            f"  run: lab deploy start {deployment_name} --user <username> --target {first_dep}"
        )


def _check_target_deps(
    target_specs: list[VMSpec],
    deployment_id: int,
    deployment_name: str,
) -> None:
    """Raise RuntimeError if any dependency of target_specs is not in the deployment."""
    batch_names = {ts.name for ts in target_specs}
    all_deps: set[str] = set()
    for spec in target_specs:
        all_deps.update(spec.depends_on)
    all_deps -= batch_names  # deps satisfied by other VMs in the same batch are fine
    if not all_deps:
        return
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM vms WHERE deployment_id=%s",
                (deployment_id,),
            )
            deployed = {r["name"] for r in cur.fetchall()}
    for dep in sorted(all_deps):
        if dep not in deployed:
            raise RuntimeError(
                f"cannot deploy — dependency '{dep}' is not deployed\n"
                f"  run: lab deploy start {deployment_name} --user <username> --target {dep}"
            )


def _build_dep_graphs_from_scenario(
    scenario_dict: dict,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Build forward and reverse dep maps from a raw scenario dict.

    Expands count: replica groups the same way parse_scenario does.
    forward[vm] = [vms that vm depends on]
    reverse[vm] = [vms that depend on vm]
    """
    vm_prefix = scenario_dict.get("vm_prefix") or ""

    count_map: dict[str, int] = {}
    for v in scenario_dict.get("vms", []):
        base = f"{vm_prefix}{v['name']}" if vm_prefix else v["name"]
        count_map[base] = v.get("count", 1)

    forward: dict[str, list[str]] = {}
    for v in scenario_dict.get("vms", []):
        base = f"{vm_prefix}{v['name']}" if vm_prefix else v["name"]
        count = v.get("count", 1)
        names = [f"{base}-{i:02d}" for i in range(1, count + 1)] if count >= 2 else [base]
        deps: list[str] = []
        for d in (v.get("depends_on") or []):
            pd = f"{vm_prefix}{d}" if vm_prefix else d
            d_count = count_map.get(pd, 1)
            if d_count >= 2:
                deps.extend(f"{pd}-{i:02d}" for i in range(1, d_count + 1))
            else:
                deps.append(pd)
        for name in names:
            forward[name] = deps

    reverse: dict[str, list[str]] = {name: [] for name in forward}
    for vm, deps in forward.items():
        for dep in deps:
            if dep in reverse:
                reverse[dep].append(vm)

    return forward, reverse


def _topo_sort_destroy_waves(
    vms: set[str],
    forward: dict[str, list[str]],
) -> list[list[str]]:
    """Group VMs into destroy waves; all VMs in a wave are independent and can be parallelised."""
    reverse_degree: dict[str, int] = {v: 0 for v in vms}
    forward_in_set: dict[str, list[str]] = {v: [] for v in vms}

    for vm in vms:
        for dep in forward.get(vm, []):
            if dep in vms:
                reverse_degree[dep] += 1
                forward_in_set[vm].append(dep)

    waves: list[list[str]] = []
    remaining = set(vms)

    while remaining:
        wave = sorted(v for v in remaining if reverse_degree[v] == 0)
        if not wave:
            waves.append(sorted(remaining))
            break
        waves.append(wave)
        for vm in wave:
            remaining.remove(vm)
            for dep in forward_in_set[vm]:
                reverse_degree[dep] -= 1

    return waves


def _topo_sort_destroy_order(
    vms: set[str],
    forward: dict[str, list[str]],
) -> list[str]:
    """Topological sort for destroy: leaf dependents first, target/dependencies last."""
    # reverse_degree[vm] = how many vms in the set depend on this vm
    reverse_degree: dict[str, int] = {v: 0 for v in vms}
    forward_in_set: dict[str, list[str]] = {v: [] for v in vms}

    for vm in vms:
        for dep in forward.get(vm, []):
            if dep in vms:
                reverse_degree[dep] += 1
                forward_in_set[vm].append(dep)

    queue = sorted(v for v in vms if reverse_degree[v] == 0)
    result: list[str] = []

    while queue:
        vm = queue.pop(0)
        result.append(vm)
        for dep in forward_in_set[vm]:
            reverse_degree[dep] -= 1
            if reverse_degree[dep] == 0:
                queue.append(dep)
                queue.sort()

    remaining = [v for v in vms if v not in set(result)]
    result.extend(sorted(remaining))
    return result


def _compute_destroy_cascade(
    target: str,
    deployed_vm_rows: list[dict],
    scenario_dict: dict,
    cascade: bool = True,
) -> tuple[list[tuple[str, str]], dict[str, list[str]]]:
    """Compute destroy order for a --target.

    target may be a single VM/group name or a comma-separated list of them
    (matching the same syntax --target accepts on `deploy start`).

    cascade=True (default): also destroys any VMs that depend on the target.
    cascade=False: destroys only the explicitly named targets, ignoring dependents.

    Returns:
        ([(vm_name, "target"|"cascaded"), ...] in destroy order, forward_deps_map)
    Raises RuntimeError if any named target is not found in deployed VMs.
    """
    deployed_names = {r["name"] for r in deployed_vm_rows}

    raw_targets = [n.strip() for n in target.split(",") if n.strip()]
    target_names: list[str] = []
    seen: set[str] = set()
    for raw_target in raw_targets:
        if raw_target in deployed_names:
            matched = [raw_target]
        else:
            replica_re = re.compile(r"^" + re.escape(raw_target) + r"-\d{2,}$")
            matched = sorted(n for n in deployed_names if replica_re.match(n))
            if not matched:
                raise RuntimeError(f"target '{raw_target}' not found in deployed VMs for this deployment")
        for name in matched:
            if name not in seen:
                target_names.append(name)
                seen.add(name)

    forward, reverse = _build_dep_graphs_from_scenario(scenario_dict)

    cascade_set: set[str] = set(target_names)
    if cascade:
        queue = list(target_names)
        while queue:
            vm = queue.pop(0)
            for dep in reverse.get(vm, []):
                if dep in deployed_names and dep not in cascade_set:
                    cascade_set.add(dep)
                    queue.append(dep)

    destroy_order = _topo_sort_destroy_order(cascade_set, forward)
    target_set = set(target_names)
    return [(vm, "target" if vm in target_set else "cascaded") for vm in destroy_order], forward


def get_target_destroy_preview(
    deployment_name: str,
    username: str,
    target: str,
    cascade: bool = True,
) -> list[tuple[str, str]]:
    """Return (vm_name, "target"|"cascaded") list in destroy order for CLI preview.

    cascade=False: only the named target VMs, dependents are not included.
    Raises RuntimeError on error (not found, no scenario stored, target not found).
    """
    user = _get_user(username)
    user_db_id: int = user["id"]

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, scenario FROM deployments "
                "WHERE user_id=%s AND name=%s AND status != 'destroyed' "
                "ORDER BY created_at DESC LIMIT 1",
                (user_db_id, deployment_name),
            )
            dep_row = cur.fetchone()

    if not dep_row:
        raise RuntimeError(f"deployment '{deployment_name}' not found for user '{username}'")

    scenario_dict = dep_row["scenario"]
    if not scenario_dict:
        raise RuntimeError(
            "dependency graph unavailable (old deployment) — "
            "destroy the full deployment without --target"
        )

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM vms WHERE deployment_id=%s",
                (dep_row["id"],),
            )
            vm_rows = [dict(r) for r in cur.fetchall()]

    result, _ = _compute_destroy_cascade(target, vm_rows, scenario_dict, cascade=cascade)
    return result


def _get_vnet_map(deployment_id: int) -> dict[str, str]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, vnet FROM networks WHERE deployment_id=%s AND vnet IS NOT NULL",
                (deployment_id,),
            )
            return {r["name"]: r["vnet"] for r in cur.fetchall()}


def _set_vm_status(deployment_id: int, vm_name: str, status: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE vms SET status=%s WHERE deployment_id=%s AND name=%s",
                (status, deployment_id, vm_name),
            )


def _set_vm_ansible_status(deployment_id: int, vm_name: str, ansible_status: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE vms SET ansible_status=%s WHERE deployment_id=%s AND name=%s",
                (ansible_status, deployment_id, vm_name),
            )


def _set_deployment_status(deployment_id: int, status: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE deployments SET status=%s, updated_at=NOW() WHERE id=%s",
                (status, deployment_id),
            )


def _check_storage_headroom(
    proxmox: ProxmoxClient,
    storage_name: str,
    log_fn: Callable[[str], None],
) -> None:
    """Log storage usage and abort if critically low.

    Thresholds:
      < 10% free  → RuntimeError (refuse to deploy, would almost certainly fail mid-clone)
      < 10–20% free  → warning logged but deploy continues
    """
    pools = proxmox.get_storage()
    pool = next((p for p in pools if p.name == storage_name), None)

    total_bytes = 0
    free_bytes = 0

    if pool and pool.type == "rbd":
        # Global /storage sums each node's view of the same shared Ceph pool,
        # inflating total by node count. Query a single node instead.
        nodes = [n for n in proxmox.get_nodes() if n.status == "online"]
        for node in nodes:
            node_pools = proxmox.get_node_storage(node.name)
            node_pool = next((p for p in node_pools if p.name == storage_name), None)
            if node_pool and node_pool.total > 0:
                total_bytes = node_pool.total
                free_bytes = node_pool.free
                break
    else:
        total_bytes = pool.total if pool else 0
        free_bytes = pool.free if pool else 0

    if total_bytes == 0:
        # Non-shared local storage: aggregate across nodes.
        nodes = [n for n in proxmox.get_nodes() if n.status == "online"]
        for node in nodes:
            node_pools = proxmox.get_node_storage(node.name)
            node_pool = next((p for p in node_pools if p.name == storage_name), None)
            if node_pool:
                total_bytes += node_pool.total
                free_bytes += node_pool.free

    if total_bytes == 0:
        log_fn(f"storage pool: {storage_name} (usage unknown)")
        return

    free_gb = free_bytes / 1024 ** 3
    total_gb = total_bytes / 1024 ** 3
    used_pct = (total_bytes - free_bytes) / total_bytes * 100

    log_fn(
        f"storage pool: {storage_name}  "
        f"{free_gb:.1f} GB free / {total_gb:.1f} GB total  ({used_pct:.1f}% used)"
    )

    free_pct = free_bytes / total_bytes * 100
    if free_pct < 10:
        raise RuntimeError(
            f"storage pool '{storage_name}' is critically full "
            f"({free_gb:.1f} GB free, {used_pct:.1f}% used) — "
            f"free space before deploying"
        )
    if free_pct < 20:
        log_fn(
            f"WARNING: storage pool '{storage_name}' is low on space "
            f"({free_gb:.1f} GB free, {used_pct:.1f}% used) — "
            f"deployment may fail mid-clone"
        )


def _auto_select_storage(proxmox: ProxmoxClient, settings: Settings) -> str:
    """Return the storage pool name for VM disks.

    Prefers: explicit setting → rbd (Ceph) → zfspool → lvmthin → first non-NFS pool.
    Raises RuntimeError if no suitable pool is found.
    """
    if settings.proxmox_storage:
        return settings.proxmox_storage
    candidates = [s for s in proxmox.get_storage() if s.type != "nfs"]
    for preferred_type in ("rbd", "zfspool", "lvmthin"):
        for s in candidates:
            if s.type == preferred_type:
                return s.name
    if candidates:
        return candidates[0].name
    raise RuntimeError("no suitable storage pool found — set PROXMOX_STORAGE in .env")


class DeployEngine:
    def start(
        self,
        scenario_path: str | Path,
        username: str,
        skip_ansible: bool = False,
        target: str | None = None,
        log_fn: Callable[[str], None] | None = None,
        no_headroom: bool = False,
    ) -> None:
        """Run the full deploy sequence for a scenario.

        Steps: resolve user → validate → parse → pre-flight templates →
        compute plan → get nodes/storage → create deployment DB row →
        create VNets → for each VM: clone, start, (SSH wait + Ansible unless skip_ansible) →
        mark deployment active.

        When target is set, only the named VM/group is deployed; an existing active or
        stopped deployment is reused (incremental add). Dependencies must already be running.

        When skip_ansible=True, VMs are created and started but ansible tasks are skipped;
        ansible_status is set to 'skipped'. Dependency checks still run normally.
        Any unhandled exception sets the deployment to failed before re-raising.
        """
        if log_fn is None:
            log_fn = print

        _force_schedule = no_headroom
        scenario_path = Path(scenario_path)
        deployment_name = scenario_path.parent.name

        # 1. Resolve user
        user = _get_user(username)
        user_db_id: int = user["id"]
        user_id: int = user["user_id"]

        # 2. Parse scenario (needed before target resolution and deployment check)
        log_fn(f"parsing scenario: {scenario_path}")
        spec = parse_scenario(scenario_path)
        scenario_raw = yaml.safe_load(scenario_path.read_text())

        # 3. Resolve target specs (if any)
        target_specs: list[VMSpec] | None = None
        if target:
            try:
                target_specs = _resolve_target(spec, target)
            except ValueError as exc:
                raise RuntimeError(str(exc))

        # 4. Check for existing deployment
        existing = _get_existing_deployment(user_db_id, deployment_name)
        deployment_id_existing: int | None = None
        _prior_status: str | None = None

        _partial_retry_full_specs: list[VMSpec] | None = None
        _already_in_target: list[VMSpec] = []
        _ansible_only_targets: list[VMSpec] = []
        _deployed_rows: dict[str, int | None] = {}
        _deployed_info: dict[str, dict] = {}

        if target_specs:
            if existing:
                status = existing["status"]
                if status == "deploying":
                    raise RuntimeError(
                        f"deployment '{deployment_name}' is currently deploying — wait for it to finish"
                    )
                # active, stopped, or failed → reuse, add target VMs to it
                # failed is allowed: the previous --target attempt may have failed before
                # creating any VM (e.g. RAM headroom), while existing VMs are still healthy
                _prior_status = _normalize_prior_status(status)
                deployment_id_existing = existing["id"]
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT name, vmid, node, management_ip, type, ansible_status FROM vms WHERE deployment_id=%s",
                            (deployment_id_existing,),
                        )
                        _deployed_info = {r["name"]: r for r in cur.fetchall()}
                        _deployed_rows = {name: row["vmid"] for name, row in _deployed_info.items()}
                        already_deployed = set(_deployed_rows.keys())

                # Split target into already-deployed (skip), ansible-only (exists —
                # e.g. created via a prior --skip-ansible Step A — but never
                # successfully provisioned), and missing (create). Non-replica
                # targets that are genuinely fully deployed still error.
                _all_replica = all(ts.replica_base for ts in target_specs)
                _missing_in_target, _already_in_target, _ansible_only_targets = _classify_target_vms(
                    target_specs, already_deployed, _deployed_info, deployment_name,
                )

                if _all_replica and _already_in_target and not _missing_in_target:
                    raise RuntimeError(
                        f"all VMs in target '{target}' are already deployed in deployment '{deployment_name}'"
                    )

                # Partial replica retry / ansible-only re-provisioning: keep the full
                # list for index calculation but only create the missing ones.
                # Ansible-only targets are never re-cloned — handled separately below
                # using their existing vmid/IP, straight from the DB.
                if _already_in_target or _ansible_only_targets:
                    if _already_in_target:
                        log_fn(
                            f"[retry] {len(_already_in_target)} replica(s) already deployed — "
                            f"deploying {len(_missing_in_target)} missing"
                        )
                    if _ansible_only_targets:
                        log_fn(
                            f"[retry] {len(_ansible_only_targets)} VM(s) already exist but were "
                            f"never provisioned — running Ansible only, no re-create"
                        )
                    _partial_retry_full_specs = target_specs
                    target_specs = _missing_in_target

                _check_target_deps(target_specs, deployment_id_existing, deployment_name)
            else:
                # No existing deployment — any dep is automatically unmet
                _check_target_deps_fresh(target_specs, deployment_name)
        else:
            # Full deploy: block if deployment already exists in a live state
            if existing:
                status = existing["status"]
                if status in ("deploying", "active", "stopped"):
                    raise RuntimeError(
                        f"deployment '{deployment_name}' is {status} — "
                        f"use --target to add VMs, or destroy it first"
                    )
                elif status == "failed":
                    log_fn(f"previous deploy of '{deployment_name}' failed — cleaning up before retry")
                    self.destroy(deployment_name, username, log_fn)

        # 5. Pre-flight template check (fail before creating any resources)
        s = get_settings()
        proxmox = ProxmoxClient(s)
        proxmox.set_log(log_fn)
        tmgr = TemplateManager(proxmox, s)

        template_vmids: dict[str, int] = {}
        ct_template_volids: dict[str, str] = {}

        online_nodes = [n for n in proxmox.get_nodes() if n.status == "online"]
        ct_resolve_node = online_nodes[0].name if online_nodes else None

        check_specs = target_specs if target_specs is not None else spec.vms
        for vm_spec in check_specs:
            if vm_spec.type == "container":
                if vm_spec.template not in ct_template_volids:
                    if ct_resolve_node is None:
                        raise RuntimeError("no online nodes available to resolve CT templates")
                    try:
                        volid = proxmox.resolve_ct_template_volid(ct_resolve_node, vm_spec.template)
                    except ValueError as exc:
                        raise RuntimeError(str(exc))
                    ct_template_volids[vm_spec.template] = volid
            else:
                if vm_spec.template not in template_vmids:
                    vmid = tmgr.get_vmid(vm_spec.template)
                    if vmid is None:
                        raise RuntimeError(
                            f"template not found: '{vm_spec.template}' — run 'lab template fetch' first"
                        )
                    template_vmids[vm_spec.template] = vmid

        # 6. Compute execution plan
        plan = [[vm.name for vm in target_specs]] if target_specs is not None else execution_plan(spec)

        # 7. Compute base_vm_index
        if target_specs is not None and deployment_id_existing is not None:
            if _partial_retry_full_specs is not None:
                # Infer the base_idx that was used in the original deploy by back-calculating
                # from an already-deployed replica's VMID and its position in the full list.
                _full_flat = {vm.name: i for i, vm in enumerate(_partial_retry_full_specs)}
                _inferred: int | None = None
                for _rs in _already_in_target:
                    if _rs.name in _deployed_rows and _deployed_rows[_rs.name] is not None:
                        _inferred = _deployed_rows[_rs.name] - user_id * 100_000 - _full_flat[_rs.name]
                        break
                base_idx = _inferred if _inferred is not None else _next_vm_index_for_deployment(deployment_id_existing, user_id)
                if _inferred is not None:
                    _claimed_vmids = {v for v in _deployed_rows.values() if v is not None}
                    _missing_names = [ts.name for ts in _missing_in_target]
                    if _inferred_base_idx_collides(base_idx, _full_flat, _missing_names, _claimed_vmids, user_id):
                        log_fn(
                            f"[retry] inferred base index {base_idx} would collide with "
                            f"VMIDs already used elsewhere in this deployment — using next free index instead"
                        )
                        base_idx = _next_vm_index_for_deployment(deployment_id_existing, user_id)
            else:
                base_idx = _next_vm_index_for_deployment(deployment_id_existing, user_id)
        else:
            base_idx = _next_base_vm_index(user_db_id)

        # 8. Get nodes + detect storage
        nodes = proxmox.get_nodes()
        storage = _auto_select_storage(proxmox, s)
        _check_storage_headroom(proxmox, storage, log_fn)

        # 9. Create or reuse deployment DB record (status='deploying')
        if target_specs is not None and deployment_id_existing is not None:
            deployment_id = deployment_id_existing
            _update_deployment_scenario(deployment_id, scenario_raw)
            _set_deployment_status(deployment_id, "deploying")
            log_fn(f"deployment {deployment_id} updated (name={deployment_name}, adding: {target})")
        else:
            deployment_id = _create_deployment(user_db_id, deployment_name, base_idx, scenario_raw)
            log_fn(f"deployment {deployment_id} created (name={deployment_name}, base_vm_index={base_idx})")

        try:
            # 10. Hot template pre-flight: ensure fast-storage copies exist for linked-clone VMs
            if target_specs is not None:
                _hot_spec = ScenarioSpec(
                    version=spec.version, name=spec.name, description=spec.description,
                    vm_prefix=spec.vm_prefix, groups=spec.groups, networks=spec.networks,
                    defaults=spec.defaults, vms=target_specs,
                )
            else:
                _hot_spec = spec
            hot_template_vmids = _prepare_hot_templates(
                _hot_spec, user_db_id, proxmox, storage, nodes, template_vmids, deployment_id, log_fn
            )

            # For partial retries use the full original replica list so missing VMs
            # get the same positions (and therefore VMIDs/IPs) as originally planned.
            _index_source = _partial_retry_full_specs or target_specs or spec.vms
            flat_index = {vm.name: i for i, vm in enumerate(_index_source)}
            failed_vms: set[str] = set()

            # IPs of standalone VMs for Ansible replica-group provisioning.
            # For incremental deploys: query already-deployed VMs from DB + compute new ones.
            if target_specs is not None and deployment_id_existing is not None:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT name, management_ip FROM vms "
                            "WHERE deployment_id=%s AND management_ip IS NOT NULL",
                            (deployment_id,),
                        )
                        standalone_vm_ips = [(r["name"], r["management_ip"]) for r in cur.fetchall()]
                standalone_vm_ips += [
                    (vm.name, ids.mgmt_ip(user_id, base_idx + flat_index[vm.name]))
                    for vm in target_specs if vm.replica_base == ""
                ]
            else:
                base_vms = target_specs if target_specs else spec.vms
                standalone_vm_ips = [
                    (v.name, ids.mgmt_ip(user_id, base_idx + flat_index[v.name]))
                    for v in base_vms
                    if v.replica_base == ""
                ]

            # Timing starts here, not after the ansible-only block below — that block
            # runs real (often slow) provisioning work, and _t_start used to be set
            # only after it completed, making the final "deployment complete" summary
            # always report ~0s for a pure ansible-only retry (e.g. `lab deploy start
            # ... --target ingest-2` re-provisioning a Step-A VM).
            _t_start = time.monotonic()
            _t_create = 0.0
            _t_provision = 0.0
            _ansible_only_t = time.monotonic()

            # Ansible-only re-provisioning: VMs (replica or standalone) that already
            # exist (e.g. created via a prior --skip-ansible Step A, or left over from
            # a batch that partially failed mid-provisioning) but never successfully
            # ran Ansible. No re-create — just ensure started, then provision using
            # their existing vmid/IP straight from the DB (they're excluded from
            # target_specs/flat_index, so the normal create-then-provision indexing
            # doesn't apply to them).
            _ansible_only_standalone = [v for v in _ansible_only_targets if not v.replica_base]
            _ansible_only_replica_groups: dict[str, list[VMSpec]] = {}
            for _v in _ansible_only_targets:
                if _v.replica_base:
                    _ansible_only_replica_groups.setdefault(_v.replica_base, []).append(_v)

            for _vm_spec in _ansible_only_standalone:
                _vm_name = _vm_spec.name
                _check_cancelled(deployment_id)
                _info = _deployed_info[_vm_name]
                _vmid_val = _info["vmid"]
                _node = _info["node"]
                _mgmt_ip = _info["management_ip"]

                log_fn(f"[{_vm_name}] already exists (VMID={_vmid_val}) — running Ansible only")
                try:
                    if _info["type"] == "container":
                        proxmox.start_ct(_node, _vmid_val, wait=True)
                    else:
                        proxmox.start_vm(_node, _vmid_val, wait=True)
                except Exception as exc:
                    if not _is_already_running_error(exc):
                        raise
                _set_vm_status(deployment_id, _vm_name, "running")

                _wait_for_ssh_ready(_mgmt_ip, _vmid_val, _vm_spec.ansible.get("connection", {}),
                                    timeout=s.deploy_ssh_timeout, deployment_id=deployment_id, log_fn=log_fn)
                _check_cancelled(deployment_id)
                _set_vm_ansible_status(deployment_id, _vm_name, "running")
                ok = _provision_vm(_vm_name, _mgmt_ip, _vm_spec, user_id, log_fn, other_vms=standalone_vm_ips)
                if not ok:
                    log_fn(f"[{_vm_name}] ansible FAILED — VM is running but not configured")
                    _set_vm_ansible_status(deployment_id, _vm_name, "failed")
                    raise RuntimeError(f"{_vm_name} ansible provisioning failed")
                _set_vm_ansible_status(deployment_id, _vm_name, "success")
                log_fn(f"[{_vm_name}] ready")

            for _base_name, _group_specs in _ansible_only_replica_groups.items():
                _group_names = [v.name for v in _group_specs]
                _group_infos = [_deployed_info[n] for n in _group_names]
                _group_ips = [i["management_ip"] for i in _group_infos]

                log_fn(f"[{_base_name}] {len(_group_names)} replica(s) already exist — running Ansible only")
                for _info, _name in zip(_group_infos, _group_names):
                    _check_cancelled(deployment_id)
                    try:
                        if _info["type"] == "container":
                            proxmox.start_ct(_info["node"], _info["vmid"], wait=True)
                        else:
                            proxmox.start_vm(_info["node"], _info["vmid"], wait=True)
                    except Exception as exc:
                        if not _is_already_running_error(exc):
                            raise
                    _set_vm_status(deployment_id, _name, "running")

                _group_conn = _group_specs[0].ansible.get("connection", {})
                for _info, _ip in zip(_group_infos, _group_ips):
                    _wait_for_ssh_ready(_ip, _info["vmid"], _group_conn,
                                        timeout=s.deploy_ssh_timeout, deployment_id=deployment_id, log_fn=log_fn)
                _check_cancelled(deployment_id)

                for _name in _group_names:
                    _set_vm_ansible_status(deployment_id, _name, "running")

                ok = _provision_replica_group(
                    base_name=_base_name,
                    group_specs=_group_specs,
                    group_ips=_group_ips,
                    ansible_section=_group_specs[0].ansible,
                    other_vms=standalone_vm_ips,
                    user_id=user_id,
                    log_fn=log_fn,
                )
                if not ok:
                    log_fn(f"[{_base_name}] ansible FAILED — VMs are running but not configured")
                    for _name in _group_names:
                        _set_vm_ansible_status(deployment_id, _name, "failed")
                    raise RuntimeError(f"{_base_name} ansible provisioning failed")
                for _name in _group_names:
                    _set_vm_ansible_status(deployment_id, _name, "success")
                    log_fn(f"[{_name}] ready")

            if _ansible_only_standalone or _ansible_only_replica_groups:
                _t_provision += time.monotonic() - _ansible_only_t

            # 11. Create scenario VNets
            _create_scenario_networks(deployment_id, user_id, spec.networks, proxmox, log_fn)
            vnet_map = _get_vnet_map(deployment_id)

            # 10. Execute plan: sequential steps.
            # Each step is split into two phases:
            #   Phase 1 — Clone + Start: all VMs in the step are cloned and started.
            #   Phase 2 — Provision: individual VMs are provisioned one-by-one;
            #              replica groups are provisioned as a single ansible-playbook batch.
            for step_vms in plan:
                step_failed = 0
                started: list[str] = []  # vm_names successfully cloned and started

                # Re-fetch node stats so each step's scheduler sees actual current RAM
                # (avoids cumulative optimistic-decrement drift across steps when VMs use
                # less than their configured maximum, which is normal with KSM/ballooning).
                nodes = proxmox.get_nodes()

                # ── Phase 1: Clone + Start ────────────────────────────────────
                _phase1_t = time.monotonic()
                # Standalone VMs (no count:) run sequentially.
                # Replica groups (count: N) use two-sub-phase parallelism:
                #   A) sequential schedule + bulk dnsmasq
                #   B) parallel Proxmox create + start (ThreadPoolExecutor, 16 workers)

                _standalone_names: list[str] = []
                _replica_groups_p1: dict[str, list[str]] = {}
                for _n in step_vms:
                    _vs = next(v for v in spec.vms if v.name == _n)
                    if _vs.replica_base:
                        _replica_groups_p1.setdefault(_vs.replica_base, []).append(_n)
                    else:
                        _standalone_names.append(_n)

                # Sequential path: standalone VMs (existing behavior)
                for vm_name in _standalone_names:
                    _check_cancelled(deployment_id)
                    vm_spec = next(v for v in spec.vms if v.name == vm_name)

                    if any(dep in failed_vms for dep in vm_spec.depends_on):
                        log_fn(f"[{vm_name}] skipping — dependency failed")
                        failed_vms.add(vm_name)
                        step_failed += 1
                        continue

                    vm_index = base_idx + flat_index[vm_name]
                    vmid_val = ids.vmid(user_id, vm_index)

                    chosen_node = schedule(nodes, vm_spec.memory, force=_force_schedule)
                    for n in nodes:
                        if n.name == chosen_node:
                            n.free_ram -= vm_spec.memory * 1024 * 1024
                            break

                    if vm_spec.type == "container":
                        log_fn(f"[{vm_name}] deploying (VMID={vmid_val}, index={vm_index}, container)")
                        try:
                            _effective_node = _create_ct(
                                deployment_id, user_id, vm_spec, vm_index,
                                ct_template_volids[vm_spec.template],
                                vnet_map, proxmox, storage, chosen_node, log_fn,
                            )
                        except Exception as exc:
                            log_fn(f"[{vm_name}] creation failed: {exc}")
                            failed_vms.add(vm_name)
                            step_failed += 1
                            break
                        proxmox.start_ct(_effective_node, vmid_val, wait=True)
                    else:
                        use_linked = vm_spec.clone_mode == "linked" and vm_spec.template in hot_template_vmids
                        template_vmid = (
                            hot_template_vmids[vm_spec.template] if use_linked
                            else template_vmids[vm_spec.template]
                        )
                        clone_label = "linked-clone" if use_linked else "full-clone"
                        log_fn(f"[{vm_name}] deploying (VMID={vmid_val}, index={vm_index}, {clone_label})")
                        try:
                            _effective_node = _create_vm(
                                deployment_id, user_id, vm_spec, vm_index,
                                template_vmid, vnet_map, proxmox, storage, chosen_node, log_fn,
                                full=not use_linked,
                            )
                        except Exception as exc:
                            log_fn(f"[{vm_name}] creation failed: {exc}")
                            failed_vms.add(vm_name)
                            step_failed += 1
                            break
                        proxmox.start_vm(_effective_node, vmid_val, wait=True)

                    log_fn(f"[{vm_name}] started on {_effective_node}")
                    started.append(vm_name)

                # Parallel path: replica groups (only if no standalone failures)
                if step_failed == 0 and _replica_groups_p1:
                    def _deploy_replica(item: dict) -> str:
                        _vm_name = item["vm_name"]
                        _vm_spec = item["vm_spec"]
                        _vm_index = item["vm_index"]
                        _vmid = item["vmid_val"]
                        _node = item["chosen_node"]
                        if item["is_ct"]:
                            log_fn(f"[{_vm_name}] deploying (VMID={_vmid}, index={_vm_index}, container)")
                        else:
                            _label = "linked-clone" if item["use_linked"] else "full-clone"
                            log_fn(f"[{_vm_name}] deploying (VMID={_vmid}, index={_vm_index}, {_label})")
                        _max_attempts = 5
                        for _attempt in range(1, _max_attempts + 1):
                            try:
                                if item["is_ct"]:
                                    _effective_node = _create_ct(
                                        deployment_id, user_id, _vm_spec, _vm_index,
                                        item["template_ref"], vnet_map, proxmox, storage, _node, log_fn,
                                        skip_dnsmasq=True,
                                    )
                                    proxmox.start_ct(_effective_node, _vmid, wait=True)
                                else:
                                    _effective_node = _create_vm(
                                        deployment_id, user_id, _vm_spec, _vm_index,
                                        item["template_ref"], vnet_map, proxmox, storage, _node, log_fn,
                                        full=not item["use_linked"], skip_dnsmasq=True,
                                    )
                                    proxmox.start_vm(_effective_node, _vmid, wait=True)
                                break
                            except Exception as exc:
                                _exc_str = str(exc)
                                if _is_already_running_error(exc):
                                    log_fn(f"[{_vm_name}] already running (started by a previous attempt whose response was lost) — treating as success")
                                    break
                                _is_retryable = (
                                    "cfs-lock" in _exc_str
                                    or "pve-storage" in _exc_str
                                    or ("lock" in _exc_str and "timeout" in _exc_str)
                                    or "no worker upid" in _exc_str
                                    or "start worker failed" in _exc_str
                                    or "Broken pipe" in _exc_str
                                    or "TLS negotiation" in _exc_str
                                    or "Interrupted system call" in _exc_str
                                    or "command socket" in _exc_str
                                )
                                # Stale VMID: exists in Proxmox but not tracked in our DB
                                # (leaked from a previous failed deploy). Delete and retry.
                                # Must check by *name*, not just vmid — a broken index
                                # calculation can compute a VMID that belongs to a
                                # completely different VM in this deployment, and treating
                                # that as "my own lost-response retry" silently skips past
                                # a real collision (or, in the not-tracked branch, deletes
                                # someone else's VM outright).
                                _is_stale_vmid = "already exists" in _exc_str
                                if _is_stale_vmid and _attempt < _max_attempts:
                                    with get_conn() as _conn:
                                        with _conn.cursor() as _cur:
                                            _cur.execute(
                                                "SELECT name FROM vms WHERE deployment_id=%s AND vmid=%s",
                                                (deployment_id, _vmid),
                                            )
                                            _row = _cur.fetchone()
                                    _tracked_name = _row["name"] if _row else None
                                    if _tracked_name is None:
                                        log_fn(f"[{_vm_name}] VMID {_vmid} already exists but not in DB — deleting stale entry")
                                        try:
                                            if item["is_ct"]:
                                                try:
                                                    proxmox.stop_ct(_node, _vmid, wait=True)
                                                except Exception:
                                                    pass
                                                proxmox.delete_ct(_node, _vmid, wait=True)
                                            else:
                                                try:
                                                    proxmox.stop_vm(_node, _vmid, wait=True)
                                                except Exception:
                                                    pass
                                                proxmox.delete_vm(_node, _vmid, wait=True)
                                        except Exception as _del_exc:
                                            log_fn(f"[{_vm_name}] failed to delete stale VMID {_vmid}: {_del_exc}")
                                            raise exc
                                        continue  # retry immediately after deletion
                                    if _tracked_name == _vm_name:
                                        # Genuinely my own earlier attempt whose response was lost.
                                        log_fn(f"[{_vm_name}] VMID {_vmid} already deployed — skipping")
                                        return _vm_name
                                    # VMID belongs to a *different* VM in this deployment —
                                    # a real index collision, not a retry artifact. Never
                                    # delete or silently skip; fail loudly instead.
                                    raise RuntimeError(
                                        f"VMID {_vmid} computed for '{_vm_name}' is already used by "
                                        f"'{_tracked_name}' in this deployment — index collision, refusing to proceed"
                                    )
                                if _is_retryable and _attempt < _max_attempts:
                                    _backoff = min(5 * (2 ** (_attempt - 1)), 60)
                                    log_fn(f"[{_vm_name}] creation failed (transient, attempt {_attempt}/{_max_attempts}) — retrying in {_backoff}s")
                                    time.sleep(_backoff)
                                else:
                                    raise
                        log_fn(f"[{_vm_name}] started on {_effective_node}")
                        return _vm_name

                    for _replica_base, _group_names in _replica_groups_p1.items():
                        # Re-fetch so each replica group sees actual RAM after the
                        # previous group's CTs were created (not just optimistic counters).
                        nodes = proxmox.get_nodes()

                        # Sub-phase A: sequential schedule + bulk dnsmasq reservation
                        _batch: list[dict] = []
                        _dhcp_entries: list[tuple[str, str]] = []
                        for vm_name in _group_names:
                            _check_cancelled(deployment_id)
                            vm_spec = next(v for v in spec.vms if v.name == vm_name)

                            if any(dep in failed_vms for dep in vm_spec.depends_on):
                                log_fn(f"[{vm_name}] skipping — dependency failed")
                                failed_vms.add(vm_name)
                                step_failed += 1
                                continue

                            vm_index = base_idx + flat_index[vm_name]
                            vmid_val = ids.vmid(user_id, vm_index)
                            chosen_node = schedule(nodes, vm_spec.memory, force=_force_schedule)
                            for n in nodes:
                                if n.name == chosen_node:
                                    n.free_ram -= vm_spec.memory * 1024 * 1024
                                    break

                            _dhcp_entries.append((ids.mac(user_id, vm_index, 0), ids.mgmt_ip(user_id, vm_index)))

                            if vm_spec.type == "container":
                                _batch.append({
                                    "vm_name": vm_name, "vm_spec": vm_spec, "vm_index": vm_index,
                                    "vmid_val": vmid_val, "chosen_node": chosen_node, "is_ct": True,
                                    "template_ref": ct_template_volids[vm_spec.template], "use_linked": False,
                                })
                            else:
                                _use_linked = vm_spec.clone_mode == "linked" and vm_spec.template in hot_template_vmids
                                _batch.append({
                                    "vm_name": vm_name, "vm_spec": vm_spec, "vm_index": vm_index,
                                    "vmid_val": vmid_val, "chosen_node": chosen_node, "is_ct": False,
                                    "template_ref": hot_template_vmids[vm_spec.template] if _use_linked else template_vmids[vm_spec.template],
                                    "use_linked": _use_linked,
                                })

                        if not _batch:
                            continue

                        dnsmasq.add_dhcp_hosts_bulk(user_id, _dhcp_entries)

                        # Sub-phase B: parallel Proxmox create + start
                        with ThreadPoolExecutor(max_workers=min(len(_batch), 16)) as pool:
                            futures = {pool.submit(_deploy_replica, item): item["vm_name"] for item in _batch}
                            for fut in as_completed(futures):
                                _vm_key = futures[fut]
                                exc = fut.exception()
                                if exc:
                                    log_fn(f"[{_vm_key}] creation failed: {exc}")
                                    failed_vms.add(_vm_key)
                                    step_failed += 1
                                else:
                                    started.append(fut.result())

                _t_create += time.monotonic() - _phase1_t

                if step_failed > 0:
                    raise RuntimeError(
                        f"{step_failed} instance(s) in execution step failed — aborting deployment"
                    )

                # ── Phase 2: Provision ────────────────────────────────────────
                _phase2_t = time.monotonic()
                if skip_ansible:
                    for vm_name in started:
                        _set_vm_status(deployment_id, vm_name, "running")
                        _set_vm_ansible_status(deployment_id, vm_name, "skipped")
                        log_fn(f"[{vm_name}] ready (ansible skipped)")
                    continue

                # Group started VMs: individual VMs are provisioned inline;
                # replicas are collected and batch-provisioned after all individual VMs.
                replica_groups: dict[str, list[str]] = {}

                for vm_name in started:
                    vm_spec = next(v for v in spec.vms if v.name == vm_name)

                    if vm_spec.replica_base:
                        replica_groups.setdefault(vm_spec.replica_base, []).append(vm_name)
                        continue

                    # Individual VM provisioning
                    vm_index = base_idx + flat_index[vm_name]
                    vmid_val = ids.vmid(user_id, vm_index)
                    mgmt_ip = ids.mgmt_ip(user_id, vm_index)

                    _wait_for_ssh_ready(mgmt_ip, vmid_val, vm_spec.ansible.get("connection", {}),
                                        timeout=s.deploy_ssh_timeout, deployment_id=deployment_id, log_fn=log_fn)
                    _check_cancelled(deployment_id)
                    _set_vm_ansible_status(deployment_id, vm_name, "running")
                    ok = _provision_vm(vm_name, mgmt_ip, vm_spec, user_id, log_fn, other_vms=standalone_vm_ips)
                    if not ok:
                        log_fn(f"[{vm_name}] ansible FAILED — VM is running but not configured")
                        _set_vm_status(deployment_id, vm_name, "running")
                        _set_vm_ansible_status(deployment_id, vm_name, "failed")
                        failed_vms.add(vm_name)
                        step_failed += 1
                        break
                    _set_vm_status(deployment_id, vm_name, "running")
                    _set_vm_ansible_status(deployment_id, vm_name, "success")
                    log_fn(f"[{vm_name}] ready")

                if step_failed > 0:
                    raise RuntimeError(
                        f"{step_failed} instance(s) in execution step failed — aborting deployment"
                    )

                # Batch provisioning for each replica group in this step
                for base_name, group_names in replica_groups.items():
                    group_specs = [next(v for v in spec.vms if v.name == n) for n in group_names]
                    group_ips = [
                        ids.mgmt_ip(user_id, base_idx + flat_index[n]) for n in group_names
                    ]
                    group_vmids = [
                        ids.vmid(user_id, base_idx + flat_index[n]) for n in group_names
                    ]

                    log_fn(f"[{base_name}] waiting for SSH on {len(group_names)} replicas...")
                    _group_conn = group_specs[0].ansible.get("connection", {})
                    for vm_name, mgmt_ip, vmid_val in zip(group_names, group_ips, group_vmids):
                        _wait_for_ssh_ready(mgmt_ip, vmid_val, _group_conn,
                                            timeout=s.deploy_ssh_timeout, deployment_id=deployment_id, log_fn=log_fn)
                    _check_cancelled(deployment_id)

                    for vm_name in group_names:
                        _set_vm_ansible_status(deployment_id, vm_name, "running")

                    ok = _provision_replica_group(
                        base_name=base_name,
                        group_specs=group_specs,
                        group_ips=group_ips,
                        ansible_section=group_specs[0].ansible,
                        other_vms=standalone_vm_ips,
                        user_id=user_id,
                        log_fn=log_fn,
                    )
                    if not ok:
                        log_fn(
                            f"[{base_name}] ansible FAILED — "
                            f"VMs are running but not configured"
                        )
                        for vm_name in group_names:
                            _set_vm_status(deployment_id, vm_name, "running")
                            _set_vm_ansible_status(deployment_id, vm_name, "failed")
                            failed_vms.add(vm_name)
                        step_failed += 1
                        break

                    for vm_name in group_names:
                        _set_vm_status(deployment_id, vm_name, "running")
                        _set_vm_ansible_status(deployment_id, vm_name, "success")
                        log_fn(f"[{vm_name}] ready")

                _t_provision += time.monotonic() - _phase2_t

                if step_failed > 0:
                    raise RuntimeError(
                        f"{step_failed} instance(s) in execution step failed — aborting deployment"
                    )

            # 11. Mark deployment active
            _set_deployment_status(deployment_id, "active")
            _t_total = time.monotonic() - _t_start
            def _fmt(s: float) -> str:
                m, sec = divmod(int(s), 60)
                return f"{m}m{sec:02d}s"
            _timing = (
                f"total {_fmt(_t_total)}"
                f" | create {_fmt(_t_create)}"
                f" | provision {_fmt(_t_provision)}"
            )
            log_fn(f"deployment complete — status: active  [{_timing}]")

        except DeploymentCancelled as exc:
            log_fn(str(exc))
        except Exception:
            _set_deployment_status(deployment_id, _status_after_failed_start(_prior_status))
            if _prior_status is not None:
                # Incremental --target add failed (e.g. ran out of RAM headroom before
                # creating anything new) — the deployment's pre-existing VMs are
                # untouched and still serving. Restore its prior status instead of
                # stamping the whole deployment 'failed', which would hide those VMs
                # from lab status / lab deploy status (both filter out 'failed').
                log_fn(
                    f"deployment '{deployment_name}' --target add failed — "
                    f"reverted status to '{_prior_status}' (existing VMs unaffected)"
                )
            raise

    def destroy(
        self,
        deployment_name: str,
        username: str,
        log_fn: Callable[[str], None] | None = None,
        target: str | None = None,
        cascade: bool = True,
    ) -> None:
        """Tear down all resources for a deployment (or a targeted subset).

        Full destroy: stop VMs → remove DHCP → delete VMs → delete VNets →
        apply SDN → mark deployment destroyed.

        Targeted destroy (target set): compute cascade from dep graph → destroy
        cascade VMs in order → clean up orphan VNets → mark deployment destroyed
        if no VMs remain, else keep active.

        cascade=False: when --target is used, only destroy the named VMs;
        dependents are left running even though their dependency is gone.

        Individual VM/VNet failures are logged but do not abort the loop.
        Returns early if already destroyed.
        """
        if log_fn is None:
            log_fn = print

        user = _get_user(username)
        user_db_id: int = user["id"]
        user_id: int = user["user_id"]

        s = get_settings()
        proxmox = ProxmoxClient(s)
        proxmox.set_log(log_fn)

        # 1. Load deployment
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status, scenario FROM deployments WHERE user_id=%s AND name=%s"
                    " ORDER BY created_at DESC LIMIT 1",
                    (user_db_id, deployment_name),
                )
                dep_row = cur.fetchone()

        if not dep_row:
            raise RuntimeError(
                f"deployment '{deployment_name}' not found for user '{username}'"
            )

        if dep_row["status"] == "destroyed":
            log_fn(f"deployment '{deployment_name}' is already destroyed — nothing to do")
            return

        deployment_id: int = dep_row["id"]

        # 2. Load VMs (include name and image for targeted destroy logic)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT name, vmid, node, mac_address, type, image FROM vms WHERE deployment_id=%s",
                    (deployment_id,),
                )
                vm_rows = [dict(r) for r in cur.fetchall()]

        # ── Targeted destroy path ─────────────────────────────────────────────
        if target:
            scenario_dict = dep_row["scenario"]
            if not scenario_dict:
                raise RuntimeError(
                    "dependency graph unavailable — destroy the full deployment without --target"
                )

            cascade, forward_deps = _compute_destroy_cascade(target, vm_rows, scenario_dict, cascade=cascade)
            cascade_names = [name for name, _ in cascade]
            cascade_set = set(cascade_names)
            cascade_vm_by_name = {r["name"]: r for r in vm_rows if r["name"] in cascade_set}

            log_fn(f"destroying {len(cascade_names)} VM(s): {', '.join(cascade_names)}")

            def _stop_and_dhcp_targeted(vm_name: str) -> None:
                vm = cascade_vm_by_name[vm_name]
                vmid = vm["vmid"]
                node = vm["node"]
                mac = vm["mac_address"]
                vm_type = vm.get("type") or "vm"
                kind = "CT" if vm_type == "container" else "VM"

                log_fn(f"[{vm_name}] stopping {kind} VMID={vmid}")
                try:
                    if vm_type == "container":
                        proxmox.stop_ct(node, vmid, wait=True)
                    else:
                        proxmox.stop_vm(node, vmid, wait=True)
                except Exception as exc:
                    log_fn(f"[{vm_name}] stop failed (continuing): {exc}")
                if mac:
                    try:
                        dnsmasq.remove_dhcp_host(user_id, mac)
                    except Exception as exc:
                        log_fn(f"[{vm_name}] DHCP removal failed (continuing): {exc}")

            def _delete_targeted(vm_name: str) -> None:
                vm = cascade_vm_by_name[vm_name]
                vmid = vm["vmid"]
                node = vm["node"]
                vm_type = vm.get("type") or "vm"
                kind = "CT" if vm_type == "container" else "VM"
                disk_volumes = [] if vm_type == "container" else proxmox.get_vm_disk_volumes(node, vmid)

                log_fn(f"[{vm_name}] deleting {kind} VMID={vmid}")
                deleted = False
                for _attempt in range(1, 4):
                    try:
                        if vm_type == "container":
                            proxmox.delete_ct(node, vmid, wait=True)
                        else:
                            proxmox.delete_vm(node, vmid, wait=True)
                        deleted = True
                        break
                    except Exception as exc:
                        if "cfs-lock" in str(exc) and _attempt < 3:
                            log_fn(f"[{vm_name}] delete failed (storage lock, attempt {_attempt}/3) — retrying in 5s")
                            time.sleep(5)
                        else:
                            log_fn(f"[{vm_name}] delete failed (continuing): {exc}")
                            break

                if not deleted:
                    # Proxmox-side resource still exists — keep the DB row so a
                    # re-run of destroy retries this VM instead of leaking it as
                    # an orphan that only `lab gc` would later find.
                    return

                for volid in disk_volumes:
                    proxmox.delete_volume(node, volid)

                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "DELETE FROM vms WHERE deployment_id=%s AND vmid=%s",
                            (deployment_id, vmid),
                        )

            for wave in _topo_sort_destroy_waves(cascade_set, forward_deps):
                with ThreadPoolExecutor(max_workers=min(len(wave), 16)) as pool:
                    futures = {pool.submit(_stop_and_dhcp_targeted, name): name for name in wave}
                    for fut in as_completed(futures):
                        exc = fut.exception()
                        if exc:
                            log_fn(f"[{futures[fut]}] stop/dhcp thread failed: {exc}")

                with ThreadPoolExecutor(max_workers=min(len(wave), _DELETE_WORKERS)) as pool:
                    futures = {pool.submit(_delete_targeted, name): name for name in wave}
                    for fut in as_completed(futures):
                        exc = fut.exception()
                        if exc:
                            log_fn(f"[{futures[fut]}] delete thread failed: {exc}")

            # Hot template cleanup: release templates no longer used by remaining VMs
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT ht.id, ht.vmid, ht.template "
                        "FROM hot_templates ht "
                        "JOIN deployment_hot_templates dht ON ht.id = dht.hot_template_id "
                        "WHERE dht.deployment_id=%s",
                        (deployment_id,),
                    )
                    hot_rows = [dict(r) for r in cur.fetchall()]

            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT DISTINCT image FROM vms WHERE deployment_id=%s AND image IS NOT NULL",
                        (deployment_id,),
                    )
                    remaining_images = {r["image"] for r in cur.fetchall()}

            for ht in hot_rows:
                if ht["template"] in remaining_images:
                    continue
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "DELETE FROM deployment_hot_templates "
                            "WHERE deployment_id=%s AND hot_template_id=%s",
                            (deployment_id, ht["id"]),
                        )
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE hot_templates SET ref_count = ref_count - 1 WHERE id=%s RETURNING ref_count",
                            (ht["id"],),
                        )
                        row = cur.fetchone()
                        new_count = row["ref_count"] if row else 0
                if new_count <= 0 and ht["vmid"] is not None:
                    log_fn(f"[hot-template VMID={ht['vmid']}] ref_count=0 — deleting")
                    for _attempt in range(1, 4):
                        try:
                            ht_node = proxmox.find_vm_node(ht["vmid"])
                            proxmox.delete_vm(ht_node, ht["vmid"], wait=True)
                            break
                        except Exception as exc:
                            if "still in use" in str(exc) and _attempt < 3:
                                log_fn(f"[hot-template VMID={ht['vmid']}] RBD still in use (attempt {_attempt}/3) — retrying in 10s")
                                time.sleep(10)
                            else:
                                log_fn(f"[hot-template VMID={ht['vmid']}] delete failed (continuing): {exc}")
                                break
                    with get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute("DELETE FROM hot_templates WHERE id=%s", (ht["id"],))

            # VNet cleanup: delete VNets no longer referenced by remaining VMs
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT DISTINCT n.vnet FROM vm_nics n
                        JOIN vms v ON v.vmid = n.vmid
                        WHERE v.deployment_id = %s AND n.vnet IS NOT NULL
                        """,
                        (deployment_id,),
                    )
                    still_used_vnets = {r["vnet"] for r in cur.fetchall()}

            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, vnet FROM networks WHERE deployment_id=%s AND vnet IS NOT NULL",
                        (deployment_id,),
                    )
                    all_nets = [dict(r) for r in cur.fetchall()]

            sdn_changed = False
            for net in all_nets:
                if net["vnet"] in still_used_vnets:
                    continue
                log_fn(f"deleting orphan VNet {net['vnet']}")
                try:
                    proxmox.delete_vnet(net["vnet"])
                    sdn_changed = True
                except Exception as exc:
                    log_fn(f"VNet {net['vnet']} delete failed (continuing): {exc}")
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM networks WHERE id=%s", (net["id"],))

            if sdn_changed:
                proxmox.apply_sdn()

            # Mark deployment destroyed if no VMs remain, otherwise back to active
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT COUNT(*) AS cnt FROM vms WHERE deployment_id=%s",
                        (deployment_id,),
                    )
                    cnt = cur.fetchone()["cnt"]

            if cnt == 0:
                _set_deployment_status(deployment_id, "destroyed")
                log_fn(f"deployment '{deployment_name}' destroyed (all VMs removed)")
            else:
                _set_deployment_status(deployment_id, "active")
                log_fn(f"target '{target}' removed — {cnt} VM(s) remain in '{deployment_name}'")
            return

        # ── Full destroy path ─────────────────────────────────────────────────

        # 3. Teardown each VM: stop + DHCP cleanup in parallel (not storage-bound),
        # then delete with limited concurrency (see _DELETE_WORKERS).
        def _stop_and_dhcp(vm: dict) -> None:
            vmid = vm["vmid"]
            node = vm["node"]
            mac = vm["mac_address"]
            vm_type = vm.get("type", "vm")

            log_fn(f"[VMID={vmid}] stopping")
            try:
                if vm_type == "container":
                    proxmox.stop_ct(node, vmid, wait=True)
                else:
                    proxmox.stop_vm(node, vmid, wait=True)
            except Exception as exc:
                log_fn(f"[VMID={vmid}] stop failed (continuing): {exc}")

            if mac:
                log_fn(f"[VMID={vmid}] removing DHCP reservation")
                try:
                    dnsmasq.remove_dhcp_host(user_id, mac)
                except Exception as exc:
                    log_fn(f"[VMID={vmid}] DHCP removal failed (continuing): {exc}")

        def _delete_vm_row(vm: dict) -> None:
            vmid = vm["vmid"]
            node = vm["node"]
            vm_type = vm.get("type", "vm")
            kind = "CT" if vm_type == "container" else "VM"
            # Read disk volumes before deletion — qmdestroy may silently skip RBD cleanup.
            disk_volumes = [] if vm_type == "container" else proxmox.get_vm_disk_volumes(node, vmid)

            log_fn(f"[VMID={vmid}] deleting {kind}")
            deleted = False
            for _attempt in range(1, 4):
                try:
                    if vm_type == "container":
                        proxmox.delete_ct(node, vmid, wait=True)
                    else:
                        proxmox.delete_vm(node, vmid, wait=True)
                    deleted = True
                    break
                except Exception as exc:
                    if "cfs-lock" in str(exc) and _attempt < 3:
                        log_fn(f"[VMID={vmid}] delete failed (storage lock, attempt {_attempt}/3) — retrying in 5s")
                        time.sleep(5)
                    else:
                        log_fn(f"[VMID={vmid}] delete failed (continuing): {exc}")
                        break

            if not deleted:
                # Proxmox-side resource still exists — keep the DB row so a
                # re-run of destroy retries this VM instead of leaking it as
                # an orphan that only `lab gc` would later find.
                return

            # Explicitly free disk volumes in case qmdestroy left them behind.
            for volid in disk_volumes:
                proxmox.delete_volume(node, volid)

            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM vms WHERE deployment_id=%s AND vmid=%s",
                        (deployment_id, vmid),
                    )

        if vm_rows:
            with ThreadPoolExecutor(max_workers=min(len(vm_rows), 16)) as pool:
                futures = {pool.submit(_stop_and_dhcp, vm): vm["vmid"] for vm in vm_rows}
                for fut in as_completed(futures):
                    exc = fut.exception()
                    if exc:
                        log_fn(f"[VMID={futures[fut]}] stop/dhcp thread failed: {exc}")

            with ThreadPoolExecutor(max_workers=min(len(vm_rows), _DELETE_WORKERS)) as pool:
                futures = {pool.submit(_delete_vm_row, vm): vm["vmid"] for vm in vm_rows}
                for fut in as_completed(futures):
                    exc = fut.exception()
                    if exc:
                        log_fn(f"[VMID={futures[fut]}] delete thread failed: {exc}")

        # 4. Decrement hot template ref_counts; delete if ref_count reaches zero.
        # Load hot templates BEFORE removing the join table rows (needed for the join).
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT ht.id, ht.vmid "
                    "FROM hot_templates ht "
                    "JOIN deployment_hot_templates dht ON ht.id = dht.hot_template_id "
                    "WHERE dht.deployment_id=%s",
                    (deployment_id,),
                )
                hot_rows = [dict(r) for r in cur.fetchall()]

        # Remove join table rows first so hot_templates rows can be deleted without FK violation.
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM deployment_hot_templates WHERE deployment_id=%s",
                    (deployment_id,),
                )

        for ht in hot_rows:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE hot_templates SET ref_count = ref_count - 1 WHERE id=%s RETURNING ref_count",
                        (ht["id"],),
                    )
                    row = cur.fetchone()
                    new_count = row["ref_count"] if row else 0

            if new_count <= 0 and ht["vmid"] is not None:
                log_fn(f"[hot-template VMID={ht['vmid']}] ref_count=0 — deleting")
                # Ceph RBD child-volume cleanup can lag behind Proxmox task completion.
                # Retry with backoff until the base volume is no longer referenced.
                deleted = False
                for attempt in range(1, 4):
                    try:
                        ht_node = proxmox.find_vm_node(ht["vmid"])
                        proxmox.delete_vm(ht_node, ht["vmid"], wait=True)
                        deleted = True
                        break
                    except Exception as exc:
                        if "still in use" in str(exc) and attempt < 3:
                            log_fn(
                                f"[hot-template VMID={ht['vmid']}] RBD still in use "
                                f"(attempt {attempt}/3) — retrying in 10s"
                            )
                            time.sleep(10)
                        else:
                            log_fn(f"[hot-template VMID={ht['vmid']}] delete failed (continuing): {exc}")
                            break
                # Always clean DB row — Proxmox VM may be gone even if delete task errored.
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM hot_templates WHERE id=%s", (ht["id"],))

        # 5. Load VNets
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, vnet FROM networks WHERE deployment_id=%s AND vnet IS NOT NULL",
                    (deployment_id,),
                )
                net_rows = [dict(r) for r in cur.fetchall()]

        # 6. Delete VNets (failures logged, not fatal)
        sdn_changed = False
        for net in net_rows:
            vnet = net["vnet"]
            log_fn(f"deleting VNet {vnet}")
            try:
                proxmox.delete_vnet(vnet)
                sdn_changed = True
            except Exception as exc:
                log_fn(f"VNet {vnet} delete failed (continuing): {exc}")
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM networks WHERE id=%s", (net["id"],))

        # 7. Apply SDN
        if sdn_changed:
            proxmox.apply_sdn()

        # 8. Mark destroyed only if every VM was actually removed from Proxmox —
        # otherwise keep the deployment active so a re-run retries the leftovers
        # instead of falsely reporting full teardown while CTs/VMs still exist.
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS cnt FROM vms WHERE deployment_id=%s",
                    (deployment_id,),
                )
                remaining = cur.fetchone()["cnt"]

        if remaining == 0:
            _set_deployment_status(deployment_id, "destroyed")
            log_fn(f"deployment '{deployment_name}' destroyed")
        else:
            _set_deployment_status(deployment_id, "active")
            log_fn(
                f"deployment '{deployment_name}' destroy incomplete — {remaining} VM(s) "
                "still exist in Proxmox (storage lock contention); re-run destroy to retry"
            )

    def stop(
        self,
        deployment_name: str,
        username: str,
        log_fn: Callable[[str], None] | None = None,
    ) -> None:
        """Stop all running VMs in a deployment without deleting them."""
        if log_fn is None:
            log_fn = print

        user = _get_user(username)
        user_db_id: int = user["id"]

        s = get_settings()
        proxmox = ProxmoxClient(s)
        proxmox.set_log(log_fn)

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM deployments WHERE user_id=%s AND name=%s"
                    " ORDER BY created_at DESC LIMIT 1",
                    (user_db_id, deployment_name),
                )
                dep_row = cur.fetchone()

        if not dep_row:
            raise RuntimeError(
                f"deployment '{deployment_name}' not found for user '{username}'"
            )

        deployment_id: int = dep_row["id"]

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, vmid, node, name, type FROM vms WHERE deployment_id=%s AND status='running'",
                    (deployment_id,),
                )
                running_vms = [dict(r) for r in cur.fetchall()]

        if not running_vms:
            log_fn("no running VMs in this deployment")
        else:
            failed: list[str] = []

            def _stop_one(vm: dict) -> None:
                log_fn(f"stopping VMID {vm['vmid']} ({vm['name']})")
                try:
                    if vm.get("type") == "container":
                        proxmox.stop_ct(vm["node"], vm["vmid"], wait=True)
                    else:
                        proxmox.stop_vm(vm["node"], vm["vmid"], wait=True)
                except Exception as exc:
                    log_fn(f"[{vm['name']}] stop failed (continuing): {exc}")
                    failed.append(vm["name"])
                    return
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE vms SET status='stopped' WHERE id=%s",
                            (vm["id"],),
                        )

            with ThreadPoolExecutor(max_workers=min(len(running_vms), 16)) as pool:
                futures = {pool.submit(_stop_one, vm): vm["name"] for vm in running_vms}
                for fut in as_completed(futures):
                    exc = fut.exception()
                    if exc:
                        log_fn(f"[{futures[fut]}] stop thread failed unexpectedly: {exc}")

            if failed:
                raise RuntimeError(f"{len(failed)} VM(s) failed to stop: {', '.join(failed)}")

        _set_deployment_status(deployment_id, "stopped")
        log_fn(f"deployment '{deployment_name}' stopped")

    def resume(
        self,
        deployment_name: str,
        username: str,
        log_fn: Callable[[str], None] | None = None,
    ) -> None:
        """Start all stopped VMs in a deployment and mark it active.

        Counterpart to stop(). Boots every VM/CT that is not already running,
        then sets deployment status back to 'active'. VMs that are already
        running are left alone. Raises RuntimeError if the deployment is not
        in 'stopped' state.
        """
        if log_fn is None:
            log_fn = print

        user = _get_user(username)
        user_db_id: int = user["id"]

        s = get_settings()
        proxmox = ProxmoxClient(s)
        proxmox.set_log(log_fn)

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status FROM deployments WHERE user_id=%s AND name=%s"
                    " ORDER BY created_at DESC LIMIT 1",
                    (user_db_id, deployment_name),
                )
                dep_row = cur.fetchone()

        if not dep_row:
            raise RuntimeError(
                f"deployment '{deployment_name}' not found for user '{username}'"
            )

        if dep_row["status"] != "stopped":
            raise RuntimeError(
                f"deployment '{deployment_name}' is {dep_row['status']} — "
                f"resume only applies to stopped deployments"
            )

        deployment_id: int = dep_row["id"]

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, vmid, node, name, type FROM vms WHERE deployment_id=%s",
                    (deployment_id,),
                )
                all_vms = [dict(r) for r in cur.fetchall()]

        if not all_vms:
            log_fn("no VMs in this deployment")
            _set_deployment_status(deployment_id, "active")
            return

        failed: list[str] = []

        def _start_one(vm: dict) -> None:
            try:
                if vm.get("type") == "container":
                    proxmox.start_ct(vm["node"], vm["vmid"], wait=True)
                else:
                    proxmox.start_vm(vm["node"], vm["vmid"], wait=True)
            except Exception as exc:
                if _is_already_running_error(exc):
                    log_fn(f"[{vm['name']}] already running — skipping")
                    return
                log_fn(f"[{vm['name']}] start failed (continuing): {exc}")
                failed.append(vm["name"])
                return
            log_fn(f"[{vm['name']}] started (VMID={vm['vmid']})")
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE vms SET status='running' WHERE id=%s",
                        (vm["id"],),
                    )

        with ThreadPoolExecutor(max_workers=min(len(all_vms), 16)) as pool:
            futures = {pool.submit(_start_one, vm): vm["name"] for vm in all_vms}
            for fut in as_completed(futures):
                exc = fut.exception()
                if exc:
                    log_fn(f"[{futures[fut]}] start thread failed unexpectedly: {exc}")

        _set_deployment_status(deployment_id, "active")
        if failed:
            log_fn(
                f"WARNING: {len(failed)} VM(s) failed to start: {', '.join(failed)} "
                f"— deployment marked active, fix those VMs manually"
            )
        log_fn(f"deployment '{deployment_name}' resumed — status: active")

    # ── snapshot / detonation-range ops ─────────────────────────────────────

    def _prep_range(self, deployment_name: str, username: str, log_fn):
        s = get_settings()
        proxmox = ProxmoxClient(s)
        proxmox.set_log(log_fn)
        user_id, deployment_id, spec, rows = _load_deployment_ops(deployment_name, username)
        return proxmox, user_id, deployment_id, spec, rows

    def snapshot_create(self, deployment_name, username, vm=None, log_fn=None):
        """Take (or refresh) the clean-baseline snapshot on each snapshot-declared VM."""
        log_fn = log_fn or print
        proxmox, _, _, spec, rows = self._prep_range(deployment_name, username, log_fn)
        targets = _snapshot_targets(spec, rows, only_vm=vm)
        if not targets:
            log_fn("no VMs declare `snapshot:` in this scenario — nothing to snapshot")
            return
        for vmspec, row in targets:
            node, vmid = row["node"], row["vmid"]
            live = vmspec.snapshot == "live"
            if proxmox.has_snapshot(node, vmid, BASELINE_SNAPSHOT):
                log_fn(f"[{vmspec.name}] refreshing baseline — deleting old '{BASELINE_SNAPSHOT}'")
                proxmox.delete_snapshot(node, vmid, BASELINE_SNAPSHOT)
            log_fn(f"[{vmspec.name}] taking {'live (RAM)' if live else 'disk'} baseline "
                   f"'{BASELINE_SNAPSHOT}' (VMID={vmid})")
            proxmox.create_snapshot(node, vmid, BASELINE_SNAPSHOT, vmstate=live,
                                    description="lab clean baseline (detonation range)")
        log_fn(f"snapshot create complete ({len(targets)} VM(s))")

    def snapshot_delete(self, deployment_name, username, vm=None, log_fn=None):
        """Remove the clean-baseline snapshot from snapshot-declared VMs."""
        log_fn = log_fn or print
        proxmox, _, _, spec, rows = self._prep_range(deployment_name, username, log_fn)
        targets = _snapshot_targets(spec, rows, only_vm=vm)
        removed = 0
        for vmspec, row in targets:
            node, vmid = row["node"], row["vmid"]
            if proxmox.has_snapshot(node, vmid, BASELINE_SNAPSHOT):
                log_fn(f"[{vmspec.name}] deleting baseline '{BASELINE_SNAPSHOT}'")
                proxmox.delete_snapshot(node, vmid, BASELINE_SNAPSHOT)
                removed += 1
            else:
                log_fn(f"[{vmspec.name}] no baseline to delete")
        log_fn(f"snapshot delete complete ({removed} removed)")

    def snapshot_list(self, deployment_name, username, log_fn=None):
        """Print which snapshot-declared VMs currently hold a baseline. Runs inline."""
        log_fn = log_fn or print
        proxmox, _, _, spec, rows = self._prep_range(deployment_name, username, log_fn)
        targets = _snapshot_targets(spec, rows, only_vm=None)
        if not targets:
            log_fn("no VMs declare `snapshot:` in this scenario")
            return
        for vmspec, row in targets:
            node, vmid = row["node"], row["vmid"]
            has = proxmox.has_snapshot(node, vmid, BASELINE_SNAPSHOT)
            flags = vmspec.snapshot + (", auto-rollback" if vmspec.rollback else "")
            state = f"baseline '{BASELINE_SNAPSHOT}' present" if has else "no baseline yet"
            log_fn(f"  {vmspec.name:<16} VMID={vmid}  [{flags}]  {state}")

    def snapshot_rollback(self, deployment_name, username, vm=None, all_vms=False, log_fn=None):
        """Manually revert baselined VM(s): --vm one, or --all (ignores the rollback flag)."""
        log_fn = log_fn or print
        if not all_vms and not vm:
            raise RuntimeError("specify --vm <name> or --all")
        proxmox, _, _, spec, rows = self._prep_range(deployment_name, username, log_fn)
        targets = _snapshot_targets(spec, rows, only_vm=None if all_vms else vm)
        if not targets:
            log_fn("no matching snapshot-declared VMs")
            return
        self._rollback_targets(proxmox, spec, targets, log_fn)
        log_fn("snapshot rollback complete")

    def _rollback_targets(self, proxmox, spec, targets, log_fn):
        """Roll each (VMSpec, row) back to the baseline in dependency order, then make
        sure each is running (a disk-only rollback leaves the VM stopped)."""
        by_name = {vs.name: (vs, row) for vs, row in targets}
        for name in _dependency_order(spec, set(by_name)):
            vmspec, row = by_name[name]
            node, vmid = row["node"], row["vmid"]
            if not proxmox.has_snapshot(node, vmid, BASELINE_SNAPSHOT):
                raise RuntimeError(
                    f"[{name}] has no '{BASELINE_SNAPSHOT}' snapshot — "
                    "run `lab snapshot create` first"
                )
            log_fn(f"[{name}] rolling back to '{BASELINE_SNAPSHOT}'")
            proxmox.rollback_snapshot(node, vmid, BASELINE_SNAPSHOT)
            try:
                running = proxmox.get_vm_status(node, vmid).status == "running"
            except Exception:
                running = False
            if not running:
                log_fn(f"[{name}] starting after disk rollback")
                try:
                    proxmox.start_vm(node, vmid, wait=True)
                except Exception as exc:
                    if not _is_already_running_error(exc):
                        raise

    def detonate(self, deployment_name, username, tactic="", revert="", settle=90,
                 per_technique=False, log_fn=None):
        """Detonation run: roll back the rollback-flagged victim(s) → wait ready →
        run the `phase: detonate` tasks (filtered by tactic) → report.

        per_technique: roll back once, then run + report each BASE technique separately
        (T1078.001/.003 → one 'T1078' report), back-to-back with no reset between."""
        log_fn = log_fn or print
        proxmox, user_id, deployment_id, spec, rows = self._prep_range(deployment_name, username, log_fn)

        # 1. Rollback set = rollback:true VMs, optionally narrowed by --revert.
        rb: list = []
        for vs in spec.vms:
            if not vs.rollback:
                continue
            row = rows.get(vs.name)
            if row and row.get("vmid") is not None:
                rb.append((vs, row))
        if revert:
            wanted = {n.strip() for n in revert.split(",") if n.strip()}
            rb = [(vs, row) for vs, row in rb if vs.name in wanted]

        if rb:
            log_fn(f"rolling back {len(rb)} victim(s) to '{BASELINE_SNAPSHOT}'")
            self._rollback_targets(proxmox, spec, rb, log_fn)
            # 2. Readiness gate: art-1 drives the victim over SSH, so wait for port 22,
            #    then settle so the Fleet agent re-checks-in and the clock resyncs (a
            #    live/RAM resume wakes with a stale clock — see memory notes).
            for vmspec, row in rb:
                log_fn(f"[{vmspec.name}] waiting for SSH (port 22) after rollback")
                try:
                    _wait_for_ssh(row["management_ip"], row["vmid"], timeout=600,
                                  deployment_id=deployment_id)
                except Exception as exc:
                    log_fn(f"[{vmspec.name}] SSH wait failed (continuing): {exc}")
            if settle > 0:
                log_fn(f"settling {settle}s for agent check-in + clock resync")
                time.sleep(settle)
        else:
            log_fn("no rollback-flagged victims — detonating against current state")

        # 3. Detonate VMs = those with any `phase: detonate` task.
        detonate_specs = [
            vs for vs in spec.vms
            if any((t or {}).get("phase") == "detonate" for t in (vs.ansible.get("tasks") or []))
        ]
        if not detonate_specs:
            raise RuntimeError("no tasks marked `phase: detonate` in this scenario — nothing to run")

        # 4. name_ip play vars (e.g. win_user_1_ip) for every deployed VM.
        other_vms = [(name, r["management_ip"]) for name, r in rows.items() if r.get("management_ip")]

        # 5. Run the detonate phase on each detonate VM.
        tsel = {t.strip() for t in tactic.split(",") if t.strip()}
        # One batch dir (yy-mm-dd-hh-mm) shared by every report from this invocation;
        # the finalizer files each report under <batch>/<tactic>/<technique>/ (+ a
        # pdf-only mirror in <batch>/reports/…). See generate_art_report.yml.
        batch = time.strftime("%y-%m-%d-%H-%M")
        overall_ok = True
        for vs in detonate_specs:
            row = rows.get(vs.name)
            if not row or not row.get("management_ip"):
                log_fn(f"[{vs.name}] not deployed / no IP — skipping")
                continue

            if per_technique:
                # One run + report per BASE technique (T1078.003 -> T1078), in file order.
                # tac_of maps each base to its scenario tactic, for report foldering (so
                # `--per-technique` with no --tactic still nests under the right tactic).
                bases: list = []
                tac_of: dict = {}
                for t in (vs.ansible.get("vars") or {}).get("atomic_tests") or []:
                    if tsel and (t.get("tactic") not in tsel):
                        continue
                    base = str(t.get("technique", "")).split(".")[0]
                    if base and base not in bases:
                        bases.append(base)
                        tac_of[base] = str(t.get("tactic", "") or "")
                if not bases:
                    log_fn(f"[{vs.name}] no techniques match tactic '{tactic or 'all'}' — skipping")
                    continue
                log_fn(f"[{vs.name}] per-technique: {len(bases)} report(s) → {', '.join(bases)}")
                for base in bases:
                    log_fn(f"[{vs.name}] detonating {base} (tactic: {tactic or 'all'})")
                    rep_tactic = tac_of.get(base) or (tactic if tactic and "," not in tactic else "") or "untagged"
                    extra = {"art_technique": base, "art_report_user": username,
                             "art_batch": batch, "art_report_tactic": rep_tactic}
                    if tactic:
                        extra["art_tactic"] = tactic
                    ok = _provision_vm(vs.name, row["management_ip"], vs, user_id, log_fn,
                                       other_vms=other_vms, run_phase="detonate", extra_vars=extra)
                    overall_ok = overall_ok and ok
            else:
                # Aggregate run: one report spanning many techniques -> batch root (no
                # tactic/technique subfolders), so no art_technique/art_report_tactic.
                extra = {"art_report_user": username, "art_batch": batch}
                if tactic:
                    extra["art_tactic"] = tactic
                log_fn(f"[{vs.name}] running detonate phase"
                       + (f" (tactic: {tactic})" if tactic else " (all tactics)"))
                ok = _provision_vm(vs.name, row["management_ip"], vs, user_id, log_fn,
                                   other_vms=other_vms, run_phase="detonate", extra_vars=extra)
                overall_ok = overall_ok and ok
        if not overall_ok:
            raise RuntimeError("one or more detonate tasks failed — see log above")
        log_fn(f"detonate complete for deployment '{deployment_name}'")

