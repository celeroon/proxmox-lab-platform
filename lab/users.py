from __future__ import annotations

import base64
import hashlib
import hmac
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from lab import dnsmasq, ids
from lab.config import Settings
from lab.db import get_conn
from lab.proxmox import ProxmoxClient

_LABMGMT_ZONE = "labmgmt"
_NETWORK_DIR = Path("/etc/systemd/network")


# ── pure helpers ──────────────────────────────────────────────────────────────

def _next_available_user_id(existing: set[int]) -> int:
    """Given a set of taken user_ids, return the next free one in 2–254."""
    for uid in range(2, 255):
        if uid not in existing:
            return uid
    raise RuntimeError("all user IDs (2–254) are allocated")


def _vnet_name(user_id: int) -> str:
    return f"mgmt{user_id}"


def _subnet_cidr(user_id: int) -> str:
    return f"10.{user_id}.0.0/16"


def _gateway_ip(user_id: int) -> str:
    return f"10.{user_id}.0.1"


def _dhcp_start(user_id: int) -> str:
    return f"10.{user_id}.0.2"


def _dhcp_end(user_id: int) -> str:
    return f"10.{user_id}.255.254"


def _link_config_content(user_id: int, mac: str) -> str:
    """Content for the systemd-networkd .link file.
    udev reads this at NIC hot-plug and renames the interface to mgmt{N}.
    """
    return (
        f"[Match]\n"
        f"MACAddress={mac}\n"
        f"\n"
        f"[Link]\n"
        f"Name=mgmt{user_id}\n"
    )


def _network_config_content(user_id: int) -> str:
    """Content for the systemd-networkd .network file for this user's mgmt NIC.
    Matches by interface name (set by the .link file), not MAC.
    """
    return (
        f"[Match]\n"
        f"Name=mgmt{user_id}\n"
        f"\n"
        f"[Network]\n"
        f"Address={_gateway_ip(user_id)}/16\n"
        f"IPForward=yes\n"
        f"IPMasquerade=ipv4\n"
    )


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    encoded = base64.urlsafe_b64encode(salt + dk).decode()
    return f"pbkdf2-sha256:{encoded}"


def _verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash.startswith("pbkdf2-sha256:"):
        return False
    encoded = stored_hash[len("pbkdf2-sha256:"):]
    raw = base64.urlsafe_b64decode(encoded.encode())
    salt, dk = raw[:16], raw[16:]
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return hmac.compare_digest(dk, check)


def generate_password(length: int = 16) -> str:
    """Generate a random URL-safe password."""
    import secrets
    return secrets.token_urlsafe(length)


# ── UserManager ───────────────────────────────────────────────────────────────

class UserManager:
    def __init__(self, client: ProxmoxClient | None, settings: Settings) -> None:
        self._client = client
        self._settings = settings

    def _allocate_user_id(self) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT user_id FROM users WHERE user_id IS NOT NULL")
                existing = {r["user_id"] for r in cur.fetchall()}
        return _next_available_user_id(existing)

    def create(
        self,
        username: str,
        password: str,
        ssh_key: str = "",
        log_fn: Callable[[str], None] = print,
    ) -> None:
        """Create a user: DB record, linux account, SDN VNet, mgmt NIC."""
        if self.get_user(username):
            raise RuntimeError(f"user '{username}' already exists")

        self._client.set_log(log_fn)

        # 1. allocate user_id — read-only, no DB write yet
        user_id = self._allocate_user_id()

        # pre-flight: if the VNet already exists in Proxmox with no matching DB record,
        # it is stale state (e.g. mgmt VM rolled back without cleaning Proxmox).
        # Auto-clean it — the VNet name is owned exclusively by this platform.
        vnet = _vnet_name(user_id)
        if self._client.vnet_exists(vnet):
            log_fn(f"removing stale VNet {vnet} (no matching user record)")
            try:
                self._client.delete_subnet(vnet, _subnet_cidr(user_id))
            except Exception:
                pass
            self._client.delete_vnet(vnet)
            # no apply_sdn here — the create flow's apply_sdn covers it

        password_hash = _hash_password(password)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (user_id, username, role, password_hash, ssh_key)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (user_id, username, "user", password_hash, ssh_key or None),
                )
        log_fn(f"user record created (user_id={user_id})")

        # 2. linux system account
        log_fn("creating linux account")
        subprocess.run(["sudo", "/usr/sbin/useradd", "-m", "-s", "/bin/bash", username], check=True)
        subprocess.run(["sudo", "/usr/sbin/chpasswd"], input=f"{username}:{password}\n", text=True, check=True)

        # 3. SSH key
        if ssh_key:
            ssh_dir = f"/home/{username}/.ssh"
            auth_keys = f"{ssh_dir}/authorized_keys"
            subprocess.run(["sudo", "mkdir", "-p", "-m", "700", ssh_dir], check=True)
            subprocess.run(["sudo", "tee", auth_keys], input=ssh_key.strip() + "\n", text=True, check=True, capture_output=True)
            subprocess.run(["sudo", "chmod", "600", auth_keys], check=True)
            subprocess.run(["sudo", "chown", "-R", f"{username}:{username}", ssh_dir], check=True)
            log_fn("SSH key added")

        # 4. Proxmox SDN VNet + subnet
        log_fn(f"creating SDN VNet {vnet}")
        self._client.create_vnet(vnet, _LABMGMT_ZONE, tag=user_id)
        self._client.create_subnet(vnet, _subnet_cidr(user_id), _gateway_ip(user_id))
        log_fn("applying SDN (may take a moment)")
        self._client.apply_sdn()

        # 5. Write .link file before NIC hot-plug so udev renames the interface on arrival
        mac = ids.mgmt_mac(user_id)
        log_fn("writing systemd-networkd interface config")
        link_path = _NETWORK_DIR / f"10-mgmt-{user_id}.link"
        subprocess.run(
            ["sudo", "tee", str(link_path)],
            input=_link_config_content(user_id, mac), text=True, check=True, capture_output=True,
        )

        # 6. hot-plug NIC to management VM
        log_fn("adding NIC to management VM")
        mgmt_node = self._client.find_vm_node(self._settings.mgmt_vmid)
        nic_slot = self._client.get_next_nic_slot(mgmt_node, self._settings.mgmt_vmid)
        self._client.add_nic(mgmt_node, self._settings.mgmt_vmid, nic_slot, vnet, mac=mac)

        # Verify the NIC actually landed — Proxmox accepts the PUT even when the
        # bridge doesn't exist yet, but silently drops the NIC on validation failure.
        nic_cfg = self._client.get_vm_nic(mgmt_node, self._settings.mgmt_vmid, nic_slot)
        if not nic_cfg or mac.lower() not in nic_cfg.lower():
            raise RuntimeError(
                f"NIC hot-plug to VMID {self._settings.mgmt_vmid} failed — {nic_slot} not found in VM "
                f"config after add. Ensure VNet '{vnet}' is applied on {mgmt_node} "
                f"(Proxmox Datacenter → SDN → Apply)."
            )
        log_fn(f"NIC {nic_slot} confirmed in VM config")

        # 7. store the NIC slot so delete can find it
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET mgmt_nic=%s WHERE username=%s",
                    (nic_slot, username),
                )

        # 8. systemd-networkd .network file + reload (interface already renamed by udev)
        network_path = _NETWORK_DIR / f"10-mgmt-{user_id}.network"
        subprocess.run(
            ["sudo", "tee", str(network_path)],
            input=_network_config_content(user_id), text=True, check=True, capture_output=True,
        )
        subprocess.run(["sudo", "networkctl", "reload"], check=True)

        # 9. dnsmasq fragment — binds to mgmt{N} and serves DHCP for 10.N.0.0/16
        log_fn("configuring dnsmasq for management network")
        dnsmasq.write_user_conf(
            user_id, _gateway_ip(user_id), _dhcp_start(user_id), _dhcp_end(user_id),
        )

        log_fn(f"done — user '{username}' ready (VNet={vnet}, NIC={nic_slot}, IP={_gateway_ip(user_id)}/16)")

    def delete(self, username: str, log_fn: Callable[[str], None] = print) -> None:
        """Delete a user and all associated resources."""
        user = self.get_user(username)
        if not user:
            raise RuntimeError(f"user '{username}' not found")

        self._client.set_log(log_fn)

        user_id = user["user_id"]
        uid = user["id"]

        # collect deployments and VMs
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM deployments WHERE user_id=%s", (uid,)
                )
                deployment_ids = [r["id"] for r in cur.fetchall()]

                vm_rows: list[dict] = []
                if deployment_ids:
                    cur.execute(
                        "SELECT vmid, node, status FROM vms WHERE deployment_id = ANY(%s)",
                        (deployment_ids,),
                    )
                    vm_rows = [dict(r) for r in cur.fetchall()]

        # 1. stop running VMs
        running = [v for v in vm_rows if v["status"] == "running"]
        if running:
            log_fn(f"stopping {len(running)} running VM(s)")
            for vm in running:
                log_fn(f"  stopping VMID {vm['vmid']}")
                try:
                    self._client.stop_vm(vm["node"], vm["vmid"], wait=True)
                except Exception as e:
                    log_fn(f"  warning: stop VMID {vm['vmid']} failed: {e}")

        # 2. destroy all VMs
        if vm_rows:
            log_fn(f"destroying {len(vm_rows)} VM(s)")
            for vm in vm_rows:
                log_fn(f"  destroying VMID {vm['vmid']}")
                try:
                    self._client.delete_vm(vm["node"], vm["vmid"], wait=True)
                except Exception as e:
                    log_fn(f"  warning: destroy VMID {vm['vmid']} failed: {e}")

        # 2b. remove scenario VNets from Proxmox (labzone, created by deploy engine)
        # DHCP reservations per VM are handled by deleting the mgmt subnet in step 4.
        if deployment_ids:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT vnet FROM networks WHERE deployment_id = ANY(%s)",
                        (deployment_ids,),
                    )
                    scenario_vnets = [r["vnet"] for r in cur.fetchall()]
            if scenario_vnets:
                log_fn(f"removing {len(scenario_vnets)} scenario VNet(s)")
                sdn_changed = False
                for vnet_name in scenario_vnets:
                    try:
                        self._client.delete_vnet(vnet_name)
                        sdn_changed = True
                    except Exception as e:
                        log_fn(f"  warning: delete VNet {vnet_name} failed: {e}")
                if sdn_changed:
                    try:
                        self._client.apply_sdn()
                    except Exception as e:
                        log_fn(f"  warning: apply_sdn after VNet cleanup failed: {e}")

        # 3. delete DB deployment/VM records (vms first — no CASCADE on vms.deployment_id)
        if deployment_ids:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM vms WHERE deployment_id = ANY(%s)", (deployment_ids,)
                    )
                    cur.execute(
                        "DELETE FROM deployments WHERE user_id=%s", (uid,)
                    )
            log_fn("deployment records removed")

        # 4. remove SDN VNet (delete subnet first, then vnet)
        if user_id:
            vnet = _vnet_name(user_id)
            log_fn(f"removing SDN VNet {vnet}")
            try:
                self._client.delete_subnet(vnet, _subnet_cidr(user_id))
            except Exception as e:
                log_fn(f"  warning: delete subnet failed: {e}")
            try:
                self._client.delete_vnet(vnet)
                self._client.apply_sdn()
            except Exception as e:
                log_fn(f"  warning: delete VNet failed: {e}")

        # 5. remove NIC from management VM
        if user["mgmt_nic"]:
            log_fn(f"removing NIC {user['mgmt_nic']} from management VM")
            try:
                mgmt_node = self._client.find_vm_node(self._settings.mgmt_vmid)
                self._client.remove_nic(mgmt_node, self._settings.mgmt_vmid, user["mgmt_nic"])
            except Exception as e:
                log_fn(f"  warning: remove NIC failed: {e}")

        # 6. delete systemd-networkd configs + dnsmasq fragment
        if user_id:
            for fname in (f"10-mgmt-{user_id}.link", f"10-mgmt-{user_id}.network"):
                subprocess.run(["sudo", "rm", "-f", str(_NETWORK_DIR / fname)])
            log_fn("network config removed")
            try:
                subprocess.run(["sudo", "networkctl", "reload"], check=True)
            except Exception as e:
                log_fn(f"  warning: networkctl reload failed: {e}")
            try:
                dnsmasq.remove_user_conf(user_id)
                log_fn("dnsmasq config removed")
            except Exception as e:
                log_fn(f"  warning: dnsmasq config removal failed: {e}")

        # 7. delete linux account
        try:
            subprocess.run(["sudo", "/usr/sbin/userdel", "-r", username], check=True)
            log_fn("linux account removed")
        except Exception as e:
            log_fn(f"  warning: userdel failed: {e}")

        # 8. delete DB user record
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username=%s", (username,))
        log_fn(f"user '{username}' deleted")

    def list_users(self) -> list[dict]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT user_id, username, role, ssh_key, mgmt_nic, created_at "
                    "FROM users ORDER BY user_id"
                )
                return [dict(r) for r in cur.fetchall()]

    def reset_password(self, username: str, password: str, log_fn: Callable[[str], None] = print) -> None:
        """Reset a user's password. Updates both the linux account and the DB hash."""
        user = self.get_user(username)
        if not user:
            raise RuntimeError(f"user '{username}' not found")
        password_hash = _hash_password(password)
        subprocess.run(["sudo", "/usr/sbin/chpasswd"], input=f"{username}:{password}\n", text=True, check=True)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password_hash=%s WHERE username=%s",
                    (password_hash, username),
                )
        log_fn(f"password reset for '{username}'")

    def get_user_vms(self, username: str) -> list[dict]:
        """Return all VMs (with status) belonging to the given user."""
        user = self.get_user(username)
        if not user:
            return []
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT v.vmid, v.node, v.status, v.name AS vm_name, d.name AS deployment_name
                    FROM vms v
                    JOIN deployments d ON v.deployment_id = d.id
                    WHERE d.user_id = %s
                    ORDER BY v.vmid
                    """,
                    (user["id"],),
                )
                return [dict(r) for r in cur.fetchall()]

    def get_user(self, username: str) -> dict | None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
                return dict(row) if row else None
