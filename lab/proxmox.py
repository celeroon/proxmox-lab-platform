from __future__ import annotations

import re
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_CT_EXT_RE = re.compile(r'\.tar\.(gz|xz|zst)$')

from proxmoxer import ProxmoxAPI

from lab.config import Settings


@dataclass
class NodeInfo:
    name: str
    status: str
    free_ram: int    # bytes
    total_ram: int   # bytes
    free_disk: int   # bytes
    total_disk: int  # bytes
    cpu_usage: float # 0.0–1.0
    cpu_total: int = 0


@dataclass
class VMStatus:
    vmid: int
    name: str
    status: str   # running | stopped | paused | template
    node: str
    description: str = ""


@dataclass
class StorageInfo:
    name: str
    type: str
    shared: bool
    free: int    # bytes
    total: int   # bytes


class ProxmoxClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._px = ProxmoxAPI(
            settings.proxmox_host,
            port=settings.proxmox_port,
            user=settings.proxmox_token_id.split("!")[0],
            token_name=settings.proxmox_token_id.split("!")[1],
            token_value=settings.proxmox_token_secret,
            verify_ssl=settings.proxmox_verify_ssl,
            timeout=300,
        )
        self._op_log: Callable[[str], None] | None = None

    def set_log(self, fn: Callable[[str], None]) -> None:
        """Attach an operation log_fn so Proxmox API writes appear in ops logs."""
        self._op_log = fn

    def _log(self, msg: str, *args) -> None:
        if self._op_log:
            self._op_log("  [px] " + (msg % args if args else msg))

    # ── nodes ─────────────────────────────────────────────────────────────────

    def get_nodes(self) -> list[NodeInfo]:
        nodes = []
        for n in self._px.nodes.get():
            if n["status"] != "online":
                nodes.append(NodeInfo(
                    name=n["node"],
                    status=n["status"],
                    free_ram=0, total_ram=0,
                    free_disk=0, total_disk=0,
                    cpu_usage=0.0,
                ))
                continue
            nodes.append(NodeInfo(
                name=n["node"],
                status=n["status"],
                free_ram=n.get("maxmem", 0) - n.get("mem", 0),
                total_ram=n.get("maxmem", 0),
                free_disk=n.get("maxdisk", 0) - n.get("disk", 0),
                total_disk=n.get("maxdisk", 0),
                cpu_usage=n.get("cpu", 0.0),
                cpu_total=n.get("maxcpu", 0),
            ))
        return nodes

    # ── storage ───────────────────────────────────────────────────────────────

    def get_storage(self) -> list[StorageInfo]:
        result = []
        for s in self._px.storage.get():
            if "images" not in (s.get("content") or ""):
                continue
            result.append(StorageInfo(
                name=s["storage"],
                type=s["type"],
                shared=bool(s.get("shared", 0)),
                free=s.get("avail", 0),
                total=s.get("total", 0),
            ))
        return result

    def get_node_storage(self, node: str) -> list[StorageInfo]:
        result = []
        for s in self._px.nodes(node).storage.get(content="images"):
            result.append(StorageInfo(
                name=s["storage"],
                type=s["type"],
                shared=bool(s.get("shared", 0)),
                free=s.get("avail", 0),
                total=s.get("total", 0),
            ))
        return result

    def get_node_rrddata(self, node: str) -> dict[str, float]:
        """Last ~1 min average netin/netout in bytes/s for a node (hourly RRD last point)."""
        try:
            data = self._px.nodes(node).rrddata.get(timeframe='hour', cf='AVERAGE')
            for entry in reversed(data):
                ni = entry.get('netin')
                no_ = entry.get('netout')
                if ni is not None and no_ is not None:
                    return {'netin': float(ni), 'netout': float(no_)}
        except Exception:
            pass
        return {'netin': 0.0, 'netout': 0.0}

    def get_ceph_io(self, node: str) -> dict[str, float]:
        """Cluster-wide Ceph IO stats (Mb/s and IOPS) from pgmap, or {} on error."""
        try:
            data = self._px.nodes(node).ceph.status.get()
            pgmap = data.get('pgmap', {})
            return {
                'read_mbps':  pgmap.get('read_bytes_sec',  0) / 1_000_000,
                'write_mbps': pgmap.get('write_bytes_sec', 0) / 1_000_000,
                'read_iops':  int(pgmap.get('read_op_per_sec',  0)),
                'write_iops': int(pgmap.get('write_op_per_sec', 0)),
            }
        except Exception:
            return {}

    # ── VMs ───────────────────────────────────────────────────────────────────

    def get_vms(self, node: str) -> list[VMStatus]:
        result = []
        for vm in self._px.nodes(node).qemu.get():
            result.append(VMStatus(
                vmid=vm["vmid"],
                name=vm.get("name", ""),
                status=vm["status"],
                node=node,
            ))
        return result

    def get_vm_status(self, node: str, vmid: int) -> VMStatus:
        vm = self._px.nodes(node).qemu(vmid).status.current.get()
        return VMStatus(
            vmid=vmid,
            name=vm.get("name", ""),
            status=vm["status"],
            node=node,
        )

    def find_vm_node(self, vmid: int) -> str:
        """Return the node name that hosts the given VMID."""
        for node in self.get_nodes():
            if node.status != "online":
                continue
            for vm in self.get_vms(node.name):
                if vm.vmid == vmid:
                    return node.name
        raise RuntimeError(f"VM {vmid} not found on any online node")

    def create_vm(
        self,
        node: str,
        vmid: int,
        template_vmid: int,
        name: str,
        cpus: int,
        memory: int,
        storage: str,
        full: bool = True,
        qemu_agent: bool = True,
        cpu_type: str | None = None,
        bios: str | None = None,
        machine: str | None = None,
        ostype: str | None = None,
        efidisk: bool = False,
        tpm: bool = False,
        vga: str | None = None,
    ) -> None:
        """Clone a template into a new VM. Waits for the clone task before configuring.

        The clone is initiated on the node that owns the template. When that differs
        from the target node and the destination storage is shared (Ceph/NFS), the
        Proxmox 'target' parameter moves the VM across nodes directly. When the
        destination storage is NOT shared (e.g. each node has its own same-named
        local-zfs pool), Proxmox rejects a direct cross-node clone outright — instead
        this clones locally on the template's node, then migrates the result onto the
        target node with its local disk (the same thing `qm migrate --with-local-disks`
        does), which Proxmox does support.

        full=False creates a linked clone (CoW overlay). The source must be a Proxmox
        template (convert_to_template must have been called). storage is only sent for
        full clones — linked clone overlay lands on the same storage as the parent.
        Callers are responsible for only requesting linked clones on shared storage —
        callers already guard this (see _prepare_hot_templates), so the migrate
        fallback below only ever applies to full clones.
        """
        template_node = self.find_vm_node(template_vmid)
        kwargs: dict = dict(newid=vmid, name=name, full=1 if full else 0)
        if full:
            kwargs["storage"] = storage

        cross_node = template_node != node
        needs_migrate = False
        if cross_node and full:
            storage_info = next((s for s in self.get_storage() if s.name == storage), None)
            needs_migrate = not (storage_info and storage_info.shared)

        # Clone and configure are kept atomic: a VM that exists but never got its
        # config is worse than no VM at all, because the caller's "already exists"
        # path would later adopt it and start a misconfigured guest.
        try:
            if needs_migrate:
                self._log("clone        node=%s vmid=%s from=%s name=%s full=%s storage=%s (local on %s, then migrate)",
                            node, vmid, template_vmid, name, full, storage, template_node)
                upid = self._px.nodes(template_node).qemu(template_vmid).clone.post(**kwargs)
                if upid:
                    self.wait_for_task(template_node, upid)
                self._log("migrate      vmid=%s %s -> %s (with local disks)", vmid, template_node, node)
                upid = self._px.nodes(template_node).qemu(vmid).migrate.post(
                    target=node, **{"with-local-disks": 1, "targetstorage": storage}
                )
                if upid:
                    self.wait_for_task(template_node, upid)
            else:
                if cross_node:
                    kwargs["target"] = node
                self._log("clone        node=%s vmid=%s from=%s name=%s full=%s storage=%s",
                            node, vmid, template_vmid, name, full, storage)
                upid = self._px.nodes(template_node).qemu(template_vmid).clone.post(**kwargs)
                if upid:
                    self.wait_for_task(template_node, upid)

            config_kwargs: dict = dict(cores=cpus, memory=memory, agent=1 if qemu_agent else 0)
            if cpu_type is not None:
                config_kwargs["cpu"] = cpu_type
            if bios is not None:
                config_kwargs["bios"] = bios
            if machine is not None:
                config_kwargs["machine"] = machine
            if ostype is not None:
                config_kwargs["ostype"] = ostype
            if vga is not None:
                config_kwargs["vga"] = vga
            # ":1" asks Proxmox to allocate the volume itself; the size it picks for these
            # is fixed by type (1M efivars, 4M TPM), so the 1 is a placeholder not a GB count.
            # pre-enrolled-keys=0 leaves Secure Boot without Microsoft's keys — a Vagrant
            # box image is not signed for it and would refuse to boot with them enrolled.
            if efidisk:
                config_kwargs["efidisk0"] = f"{storage}:1,efitype=4m,pre-enrolled-keys=0"
            if tpm:
                config_kwargs["tpmstate0"] = f"{storage}:1,version=v2.0"
            self._log("config       vmid=%s %s", vmid,
                      " ".join(f"{k}={v}" for k, v in config_kwargs.items() if k not in ("cores", "memory")))
            self._px.nodes(node).qemu(vmid).config.put(**config_kwargs)
        except Exception:
            if self.vm_exists(vmid):
                self._log("cleanup      vmid=%s partial clone (create failed), deleting", vmid)
                try:
                    self.delete_vm(self.find_vm_node(vmid), vmid)
                except Exception:
                    self._log("cleanup      vmid=%s could not be removed — delete it manually", vmid)
            raise

    def start_vm(self, node: str, vmid: int, wait: bool = True) -> None:
        self._log("start_vm     node=%s vmid=%s", node, vmid)
        upid = self._px.nodes(node).qemu(vmid).status.start.post()
        if wait and upid:
            self.wait_for_task(node, upid)

    def stop_vm(self, node: str, vmid: int, wait: bool = True) -> None:
        """Force-stop a VM (immediate, equivalent to pulling the power)."""
        self._log("stop_vm      node=%s vmid=%s", node, vmid)
        upid = self._px.nodes(node).qemu(vmid).status.stop.post()
        if wait and upid:
            self.wait_for_task(node, upid)

    def shutdown_vm(self, node: str, vmid: int, wait: bool = True) -> None:
        """Graceful ACPI shutdown."""
        self._log("shutdown_vm  node=%s vmid=%s", node, vmid)
        upid = self._px.nodes(node).qemu(vmid).status.shutdown.post()
        if wait and upid:
            self.wait_for_task(node, upid)

    def delete_vm(self, node: str, vmid: int, wait: bool = True) -> None:
        self._log("delete_vm    node=%s vmid=%s", node, vmid)
        upid = self._px.nodes(node).qemu(vmid).delete()
        if wait and upid:
            self.wait_for_task(node, upid)

    # efidisk/tpmstate are included so UEFI guests don't leak their NVRAM volumes.
    _DISK_KEY_RE = re.compile(r'^(scsi|virtio|ide|sata|efidisk|tpmstate)\d+$')

    def get_vm_disk_volumes(self, node: str, vmid: int) -> list[str]:
        """Return full volume IDs for a VM's data disks (e.g. 'pmoxpool1:vm-200001-disk-0').

        Called before delete_vm so we can explicitly free volumes that qmdestroy may silently
        skip when RBD removal fails internally.
        """
        try:
            config = self._px.nodes(node).qemu(vmid).config.get()
        except Exception:
            return []
        volids = []
        for key, val in config.items():
            if not self._DISK_KEY_RE.match(key):
                continue
            val = str(val)
            if ":" not in val:
                continue
            storage, rest = val.split(":", 1)
            image = rest.split(",")[0]
            if image.startswith(("none", "cloudinit")):
                continue
            volids.append(f"{storage}:{image}")
        return volids

    def delete_volume(self, node: str, volid: str) -> None:
        """Delete a storage volume by full volume ID (e.g. 'pmoxpool1:vm-200001-disk-0').

        Silently ignores errors — the volume may already be gone.
        """
        storage = volid.split(":")[0]
        try:
            upid = self._px.nodes(node).storage(storage).content(volid).delete()
            if upid and isinstance(upid, str):
                self.wait_for_task(node, upid)
        except Exception:
            pass

    def get_vm_config(self, node: str, vmid: int) -> dict:
        return self._px.nodes(node).qemu(vmid).config.get()

    def get_next_nic_slot(self, node: str, vmid: int) -> str:
        """Return the lowest unused netN slot on a VM (e.g. 'net1')."""
        config = self.get_vm_config(node, vmid)
        for i in range(32):
            if f"net{i}" not in config:
                return f"net{i}"
        raise RuntimeError(f"VM {vmid} has no free NIC slots (all net0–net31 in use)")

    def add_nic(self, node: str, vmid: int, iface: str, vnet: str, mac: str = "") -> None:
        """Add a network interface to a VM. Specifying mac makes the NIC deterministic."""
        self._log("add_nic      node=%s vmid=%s slot=%s vnet=%s mac=%s", node, vmid, iface, vnet, mac)
        value = f"virtio={mac},bridge={vnet}" if mac else f"virtio,bridge={vnet}"
        self._px.nodes(node).qemu(vmid).config.put(**{iface: value})

    def get_vm_nic(self, node: str, vmid: int, slot: str) -> str | None:
        """Return the NIC config string for a slot, or None if the slot is absent."""
        try:
            return self._px.nodes(node).qemu(vmid).config.get().get(slot)
        except Exception:
            return None

    def remove_nic(self, node: str, vmid: int, iface: str) -> None:
        """Remove a network interface from a VM (hot-unplug if running)."""
        self._log("remove_nic   node=%s vmid=%s slot=%s", node, vmid, iface)
        self._px.nodes(node).qemu(vmid).config.put(delete=iface)

    def set_vm_mac(self, node: str, vmid: int, iface: str, mac: str, vnet: str) -> None:
        self._log("set_vm_mac   node=%s vmid=%s slot=%s mac=%s vnet=%s", node, vmid, iface, mac, vnet)
        self._px.nodes(node).qemu(vmid).config.put(**{
            iface: f"virtio={mac},bridge={vnet}"
        })

    def get_templates(self, node: str) -> list[VMStatus]:
        """Return all VMs marked as templates on a node."""
        result = []
        for vm in self._px.nodes(node).qemu.get():
            if vm.get("template"):
                vmid = vm["vmid"]
                try:
                    cfg = self._px.nodes(node).qemu(vmid).config.get()
                    desc = cfg.get("description", "")
                except Exception:
                    desc = ""
                result.append(VMStatus(
                    vmid=vmid,
                    name=vm.get("name", ""),
                    status="template",
                    node=node,
                    description=desc,
                ))
        return result

    def convert_to_template(self, node: str, vmid: int) -> None:
        self._log("mk_template  node=%s vmid=%s", node, vmid)
        self._px.nodes(node).qemu(vmid).template.post()

    def create_blank_vm(self, node: str, vmid: int, name: str, memory: int = 2048, cores: int = 2, description: str = "") -> None:
        self._log("create_vm    node=%s vmid=%s name=%s", node, vmid, name)
        self._px.nodes(node).qemu.post(
            vmid=vmid,
            name=name,
            memory=memory,
            cores=cores,
            scsihw="virtio-scsi-pci",
            description=description,
        )

    def rename_vm(self, node: str, vmid: int, new_name: str, description: str = "") -> None:
        kwargs: dict[str, str] = {"name": new_name}
        if description:
            kwargs["description"] = description
        self._px.nodes(node).qemu(vmid).config.put(**kwargs)

    def import_disk(self, node: str, vmid: int, file_path: str, storage: str, disk: str = "scsi0") -> str | None:
        """Attach an existing NFS volume as a VM disk.

        file_path must be a Proxmox volume reference already on shared storage
        (e.g. 'nfs-templates:9001/vm-9001-disk-0.qcow2'). The file is registered
        in the VM config in-place — no copy is made, so this returns immediately.
        """
        # Scan storage so Proxmox indexes the newly-copied file before referencing it.
        self._px.nodes(node).storage(storage).content.get()
        return self._px.nodes(node).qemu(vmid).config.put(**{
            disk: file_path,
            "boot": f"order={disk}",
        })

    def wait_for_task(self, node: str, upid: str, timeout: int = 600, interval: float = 3.0) -> None:
        """Poll a Proxmox task until it completes. Raises RuntimeError on failure or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self._px.nodes(node).tasks(upid).status.get()
            if result.get("status") == "stopped":
                if result.get("exitstatus") == "OK":
                    return
                raise RuntimeError(f"Proxmox task failed: {result.get('exitstatus')}")
            time.sleep(interval)
        raise TimeoutError(f"Proxmox task did not complete within {timeout}s: {upid}")

    # ── SDN ───────────────────────────────────────────────────────────────────

    def vm_exists(self, vmid: int) -> bool:
        """Return True if a VM with this VMID exists on any online node."""
        for node in self.get_nodes():
            if node.status != "online":
                continue
            for vm in self.get_vms(node.name):
                if vm.vmid == vmid:
                    return True
        return False

    def vnet_exists(self, vnet: str) -> bool:
        """Return True if a VNet with this name already exists in Proxmox SDN."""
        vnets = self._px.cluster.sdn.vnets.get()
        return any(v["vnet"] == vnet for v in vnets)

    def create_vnet(self, vnet: str, zone: str, tag: int | None = None) -> None:
        self._log("create_vnet  vnet=%s zone=%s tag=%s", vnet, zone, tag)
        kwargs: dict = {"vnet": vnet, "zone": zone}
        if tag is not None:
            kwargs["tag"] = tag
        self._px.cluster.sdn.vnets.post(**kwargs)

    def create_subnet(self, vnet: str, subnet: str, gateway: str) -> None:
        self._log("create_subnet vnet=%s subnet=%s gw=%s", vnet, subnet, gateway)
        self._px.cluster.sdn.vnets(vnet).subnets.post(
            subnet=subnet, type="subnet", gateway=gateway,
        )

    def delete_subnet(self, vnet: str, subnet_cidr: str) -> None:
        """Delete a subnet by CIDR. Lists subnets to find the Proxmox internal ID.
        Proxmox subnet IDs include the zone prefix: 'labmgmt-10.2.0.0-16'."""
        self._log("delete_subnet vnet=%s cidr=%s", vnet, subnet_cidr)
        subnets = self._px.cluster.sdn.vnets(vnet).subnets.get()
        for s in subnets:
            if s.get("cidr") == subnet_cidr:
                self._px.cluster.sdn.vnets(vnet).subnets(s["id"]).delete()
                return

    def delete_vnet(self, vnet: str) -> None:
        self._log("delete_vnet  vnet=%s", vnet)
        self._px.cluster.sdn.vnets(vnet).delete()

    def apply_sdn(self) -> None:
        """Apply pending SDN config changes and wait for completion."""
        self._log("apply_sdn")
        upid = self._px.cluster.sdn.put()
        if upid and isinstance(upid, str) and ":" in upid:
            node = upid.split(":")[1]
            self.wait_for_task(node, upid)

    def list_vnets(self) -> list[dict]:
        """Return all VNets from Proxmox SDN. Each dict has 'vnet' and 'zone' keys."""
        return self._px.cluster.sdn.vnets.get()

    # ── cluster resources ─────────────────────────────────────────────────────

    def get_cluster_resources(self, resource_type: str) -> list[dict]:
        """Return cluster resource list for the given type ('node' or 'vm').

        Each dict is the raw Proxmox API record.  Node fields include: node,
        status, cpu, maxcpu, mem, maxmem, disk, maxdisk.  VM fields include:
        vmid, name, status, node, template.
        """
        return self._px.cluster.resources.get(type=resource_type)

    # ── console ───────────────────────────────────────────────────────────────

    def get_vnc_ticket(self, node: str, vmid: int, vm_type: str = "vm") -> dict:
        """Request a noVNC ticket for a running VM or CT.

        Returns a dict with keys: ticket (str), port (int), cert (str).
        The ticket is short-lived — build and open the URL immediately.
        """
        if vm_type == "container":
            return self._px.nodes(node).lxc(vmid).vncproxy.post(websocket=1)
        return self._px.nodes(node).qemu(vmid).vncproxy.post(websocket=1)

    # ── CT templates ──────────────────────────────────────────────────────────

    def list_ct_templates(self, node: str) -> list[str]:
        """Return sorted list of available CT template names without file extension."""
        entries = self._px.nodes(node).aplinfo.get()
        names = []
        for e in entries:
            if e.get("section") == "system":
                filename = e.get("template", "")
                names.append(_CT_EXT_RE.sub("", filename))
        return sorted(names)

    def fetch_ct_template(self, node: str, name: str, storage: str = "nfs-templates") -> None:
        """Download a CT template by name (without extension) to shared NFS storage.

        Raises ValueError if name not found in the available template list.
        """
        entries = self._px.nodes(node).aplinfo.get()
        entry = None
        for e in entries:
            if e.get("section") == "system":
                full = e.get("template", "")
                if _CT_EXT_RE.sub("", full) == name:
                    entry = e
                    break
        if entry is None:
            raise ValueError(f"CT template not found: {name!r} — run 'lab template ct list'")
        filename = entry["template"]
        location = (entry.get("location")
                    or f"http://download.proxmox.com/images/system/{filename}")
        upid = self._px.nodes(node).storage(storage)("download-url").post(
            url=location,
            filename=filename,
            content="vztmpl",
        )
        try:
            self.wait_for_task(node, upid)
        except RuntimeError as exc:
            if "refusing to override" in str(exc):
                raise FileExistsError(f"{filename} is already downloaded")
            raise
        self._patch_ct_sshd(filename)

    def _patch_ct_sshd(self, filename: str) -> None:
        """Patch PermitRootLogin yes into a CT template tarball.

        The management VM is the NFS server, so templates_dir is directly writable.
        Called automatically after every CT template download.
        """
        path = Path(self._settings.templates_dir) / "template" / "cache" / filename
        if not path.exists():
            return
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(
                ["tar", "--numeric-owner", "-xf", str(path), "-C", tmpdir],
                check=True, capture_output=True,
            )
            sshd = Path(tmpdir) / "etc" / "ssh" / "sshd_config"
            if sshd.exists():
                txt = sshd.read_text()
                txt = re.sub(r'^#*PermitRootLogin.*', 'PermitRootLogin yes', txt, flags=re.MULTILINE)
                if 'PermitRootLogin' not in txt:
                    txt += '\nPermitRootLogin yes\n'
                sshd.write_text(txt)
            tmp_path = path.with_suffix(".patching")
            try:
                subprocess.run(
                    ["tar", "--numeric-owner", "-czf", str(tmp_path), "-C", tmpdir, "."],
                    check=True, capture_output=True,
                )
                path.unlink()
                tmp_path.rename(path)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise

    def list_downloaded_ct_templates(self, node: str, storage: str = "nfs-templates") -> list[str]:
        """Return sorted list of CT template names already downloaded to storage."""
        content = self._px.nodes(node).storage(storage).content.get(content="vztmpl")
        names = []
        for item in content:
            volid = item.get("volid", "")
            filename = volid.split("/")[-1] if "/" in volid else volid
            names.append(_CT_EXT_RE.sub("", filename))
        return sorted(names)

    def resolve_ct_template_volid(self, node: str, name: str, storage: str = "nfs-templates") -> str:
        """Return the full Proxmox volume ID for a downloaded CT template.

        Raises ValueError if the template is not found in storage.
        """
        content = self._px.nodes(node).storage(storage).content.get(content="vztmpl")
        for item in content:
            volid = item.get("volid", "")
            filename = volid.split("/")[-1] if "/" in volid else volid
            if _CT_EXT_RE.sub("", filename) == name:
                return volid
        raise ValueError(
            f"CT template '{name}' not found in {storage} "
            f"— run 'lab template ct fetch {name}' first"
        )

    def ct_exists(self, vmid: int) -> bool:
        """Return True if a container with this VMID exists on any online node."""
        for node in self.get_nodes():
            if node.status != "online":
                continue
            for ct in self._px.nodes(node.name).lxc.get():
                if ct["vmid"] == vmid:
                    return True
        return False

    def find_ct_node(self, vmid: int) -> str:
        """Return the node name that hosts the given container VMID."""
        for node in self.get_nodes():
            if node.status != "online":
                continue
            for ct in self._px.nodes(node.name).lxc.get():
                if ct["vmid"] == vmid:
                    return node.name
        raise RuntimeError(f"container {vmid} not found on any online node")

    def create_ct(
        self,
        node: str,
        vmid: int,
        ostemplate: str,
        name: str,
        cpus: int,
        memory: int,
        storage: str,
        net_params: dict[str, str],
        disk_gb: int = 4,
    ) -> None:
        """Create an LXC container from a downloaded CT template.

        net_params maps slot → net string (e.g. {"net0": "name=eth0,bridge=mgmt2,hwaddr=..."}).
        disk_gb controls rootfs size (default 4 GB; use 8+ for agent containers that extract large tarballs).
        password="vagrant" enables console and SSH login as root (root/vagrant).
        features=nesting=1 is required for systemd to boot properly in an unprivileged container.
        """
        kwargs: dict = dict(
            vmid=vmid,
            ostemplate=ostemplate,
            hostname=name,
            cores=cpus,
            memory=memory,
            rootfs=f"{storage}:{disk_gb}",
            unprivileged=1,
            password="vagrant",
            features="nesting=1",
        )
        kwargs.update(net_params)
        self._log("create_ct    node=%s vmid=%s name=%s tmpl=%s", node, vmid, name, ostemplate)
        upid = self._px.nodes(node).lxc.post(**kwargs)
        if upid:
            self.wait_for_task(node, upid)

    def start_ct(self, node: str, vmid: int, wait: bool = True) -> None:
        self._log("start_ct     node=%s vmid=%s", node, vmid)
        upid = self._px.nodes(node).lxc(vmid).status.start.post()
        if wait and upid:
            self.wait_for_task(node, upid)

    def stop_ct(self, node: str, vmid: int, wait: bool = True) -> None:
        self._log("stop_ct      node=%s vmid=%s", node, vmid)
        upid = self._px.nodes(node).lxc(vmid).status.stop.post()
        if wait and upid:
            self.wait_for_task(node, upid)

    def delete_ct(self, node: str, vmid: int, wait: bool = True) -> None:
        self._log("delete_ct    node=%s vmid=%s", node, vmid)
        upid = self._px.nodes(node).lxc(vmid).delete()
        if wait and upid:
            self.wait_for_task(node, upid)

