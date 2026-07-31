from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO

import httpx

from lab.config import Settings
from lab.proxmox import ProxmoxClient, VMStatus

TEMPLATE_VMID_MIN = 9000
TEMPLATE_VMID_MAX = 9999
_NFS_STORAGE = "nfs-templates"
_VAGRANT_API = "https://app.vagrantup.com/api/v2/box"
_COPY_CHUNK = 4 << 20
_CACHE_DROP_BYTES = 256 << 20   # bytes written between page-cache drops while extracting
_CACHE_DROP_INTERVAL = 5.0      # seconds between page-cache drops while downloading
_DOWNLOAD_TIMEOUT = 3 * 60 * 60


def next_template_vmid(existing_vmids: list[int]) -> int:
    """Return the lowest free VMID in 9000–9999."""
    used = set(existing_vmids)
    for vmid in range(TEMPLATE_VMID_MIN, TEMPLATE_VMID_MAX + 1):
        if vmid not in used:
            return vmid
    raise RuntimeError("template VMID range 9000–9999 is exhausted")


def box_to_name(box: str) -> str:
    """Convert 'generic-x64/debian12' to 'generic-x64-debian12'."""
    return box.replace("/", "-")


def _get_download_url(box: str) -> str:
    user, name = box.split("/", 1)
    resp = httpx.get(f"{_VAGRANT_API}/{user}/{name}", timeout=15)
    resp.raise_for_status()
    data = resp.json()
    providers = [p for p in data["current_version"]["providers"] if p["name"] == "libvirt"]
    if not providers:
        raise RuntimeError(
            f"no libvirt provider found for '{box}' — only QEMU/libvirt boxes are supported"
        )
    # One provider entry per architecture; take the box's default rather than the first listed.
    for provider in providers:
        if provider.get("default_architecture"):
            return provider["download_url"]
    return providers[0]["download_url"]


def _drop_cache(fd: int, offset: int = 0, length: int = 0) -> None:
    """Release fd's clean page cache (whole file when length is 0).

    Boxes run to ~13 GB compressed and ~15 GB extracted. Left cached, a single
    fetch evicts everything else on the management VM and reports as 100% memory
    use, since the kernel counts page cache as used.
    """
    try:
        os.posix_fadvise(fd, offset, length, os.POSIX_FADV_DONTNEED)
    except OSError:
        pass


def _drop_cache_path(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        _drop_cache(fd)
    finally:
        os.close(fd)


def _download(url: str, dest: Path) -> None:
    """Download url to dest via wget, resuming any previous partial transfer.

    wget uses GnuTLS rather than OpenSSL, avoiding SSL record-layer failures
    seen with both curl and httpx on Vagrant Cloud CDN long-running downloads.

    -nv rather than -q: -q suppresses wget's error line too, which leaves a
    failure with no diagnosis at all. The .part file is kept on failure on
    purpose — the CDN redirects to a presigned URL valid for only 900s, so a
    13 GB box on a link slower than ~15 MB/s cannot finish in one attempt and
    has to resume across runs.
    """
    part = dest.with_suffix(dest.suffix + ".part")
    part.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "wget", "-nv", "-c",
        "--tries=10",
        "--waitretry=15",
        "--timeout=60",   # wget's 900s default read timeout outlives the presigned URL
        "-O", str(part),
        url,
    ]
    with tempfile.TemporaryFile("w+") as errfile:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errfile)
        deadline = time.monotonic() + _DOWNLOAD_TIMEOUT
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f"download exceeded {_DOWNLOAD_TIMEOUT // 3600}h — "
                        "partial file kept, re-run to resume"
                    )
                time.sleep(_CACHE_DROP_INTERVAL)
                _drop_cache_path(part)
        except BaseException:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            raise
        errfile.seek(0)
        stderr = errfile.read()

    if proc.returncode != 0:
        lines = [ln for ln in stderr.strip().splitlines() if ln.strip()]
        detail = lines[-1] if lines else f"wget exited {proc.returncode}"
        raise RuntimeError(f"{detail} — partial file kept, re-run to resume")
    _drop_cache_path(part)
    part.rename(dest)


def _copy_release_cache(src: IO[bytes], dst: IO[bytes], src_fd: int) -> None:
    """Copy src → dst, releasing page cache for both as the copy progresses."""
    dst_fd = dst.fileno()
    written = dropped = 0
    while True:
        chunk = src.read(_COPY_CHUNK)
        if not chunk:
            break
        dst.write(chunk)
        written += len(chunk)
        if written - dropped >= _CACHE_DROP_BYTES:
            dst.flush()
            os.fsync(dst_fd)
            _drop_cache(dst_fd, dropped, written - dropped)
            _drop_cache(src_fd)
            dropped = written
    dst.flush()
    os.fsync(dst_fd)
    _drop_cache(dst_fd)
    _drop_cache(src_fd)


def _extract_qcow2(box_path: Path, dest: Path) -> None:
    """Stream the box's disk image out of the tar.gz into dest.

    Stream mode ("r|gz") reads the archive exactly once. The seekable mode needs
    a full member index before it can extract anything, which decompresses the
    whole archive an extra time — ~13 GB of wasted reads for a Windows box.
    Member names are not fixed: HashiCorp-hosted boxes nest the disk in a
    numbered directory ('15140074115/box_0.img'), so match on suffix.
    """
    seen: list[str] = []
    with open(box_path, "rb") as raw:
        with tarfile.open(fileobj=raw, mode="r|gz") as tar:
            for member in tar:
                seen.append(member.name)
                if not member.isfile():
                    continue
                if not Path(member.name).name.endswith((".img", ".qcow2")):
                    continue
                stream = tar.extractfile(member)
                if stream is None:
                    raise RuntimeError(f"could not read {member.name} from archive")
                with stream, dest.open("wb") as dst:
                    _copy_release_cache(stream, dst, raw.fileno())
                return
    raise RuntimeError(
        f"no disk image found in {box_path.name} — "
        f"contents: {seen} — is this a libvirt/QEMU box?"
    )


class TemplateManager:
    def __init__(self, client: ProxmoxClient, settings: Settings) -> None:
        self._client = client
        self._settings = settings

    def _collect(self) -> list[VMStatus]:
        """All template VMs in the 9000–9999 range across all online nodes (deduped by VMID)."""
        seen: set[int] = set()
        result = []
        for node in self._client.get_nodes():
            if node.status != "online":
                continue
            for t in self._client.get_templates(node.name):
                if TEMPLATE_VMID_MIN <= t.vmid <= TEMPLATE_VMID_MAX and t.vmid not in seen:
                    seen.add(t.vmid)
                    result.append(t)
        return result

    def _all_vmids_in_range(self) -> list[int]:
        """All VMIDs in 9000–9999 — templates, plain VMs, and in-progress NFS slot directories.

        NFS directories are included so that concurrent fetches (which create the directory
        before Proxmox sees the VM) don't collide on the same VMID.
        """
        seen: set[int] = set()
        for node in self._client.get_nodes():
            if node.status != "online":
                continue
            for vm in self._client.get_vms(node.name):
                if TEMPLATE_VMID_MIN <= vm.vmid <= TEMPLATE_VMID_MAX:
                    seen.add(vm.vmid)
        images_dir = Path(self._settings.templates_dir) / "images"
        if images_dir.exists():
            for d in images_dir.iterdir():
                if d.is_dir() and d.name.isdigit():
                    vmid = int(d.name)
                    if TEMPLATE_VMID_MIN <= vmid <= TEMPLATE_VMID_MAX:
                        seen.add(vmid)
        return list(seen)

    def _prepare_nfs_slot(self, vmid: int) -> tuple[Path, Path]:
        """Create the NFS images/{vmid}/ directory and return (vm_dir, qcow2_path)."""
        templates_dir = Path(self._settings.templates_dir)
        vm_dir = templates_dir / "images" / str(vmid)
        vm_dir.mkdir(parents=True, exist_ok=True)
        disk_name = f"vm-{vmid}-disk-0.qcow2"
        return vm_dir, vm_dir / disk_name

    def _allocate_slot(self) -> tuple[int, Path, Path]:
        """Atomically allocate a VMID and create the NFS slot directory.

        An exclusive flock on .fetch.lock serializes the scan+pick+mkdir critical section
        so that concurrent template fetches never receive the same VMID.
        The lock is released before the (slow) download begins.
        """
        lock_path = Path(self._settings.templates_dir) / ".fetch.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            vmid = next_template_vmid(self._all_vmids_in_range())
            vm_dir, qcow2_path = self._prepare_nfs_slot(vmid)
        return vmid, vm_dir, qcow2_path

    def _run_import(
        self,
        node: str,
        vmid: int,
        name: str,
        qcow2_path: Path,
        log_fn: Callable[[str], None],
        description: str = "",
    ) -> None:
        """Blank VM → import disk → convert to template. Cleans up VM and disk on failure."""
        storage_path = f"{_NFS_STORAGE}:{vmid}/{qcow2_path.name}"
        vm_created = False
        try:
            log_fn(f"creating blank VM (VMID {vmid})")
            self._client.create_blank_vm(node, vmid, name, description=description)
            vm_created = True

            log_fn("importing disk")
            upid = self._client.import_disk(node, vmid, storage_path, _NFS_STORAGE)
            if upid:
                self._client.wait_for_task(node, upid)

            log_fn("converting to template")
            self._client.convert_to_template(node, vmid)
        except Exception:
            if vm_created:
                log_fn(f"error: cleaning up VM {vmid} after failure")
                try:
                    self._client.delete_vm(node, vmid)
                except Exception:
                    pass
            qcow2_path.unlink(missing_ok=True)
            try:
                qcow2_path.parent.rmdir()
            except OSError:
                pass
            raise

    def list(self) -> list[VMStatus]:
        return self._collect()

    def get_vmid(self, name: str) -> int | None:
        """Look up a template VMID by name. Accepts both 'user/box' and 'user-box' forms."""
        target = box_to_name(name) if "/" in name else name
        for t in self._collect():
            if t.name == target:
                return t.vmid
        return None

    def cleanup_orphaned_slots(self) -> list[int]:
        """Remove NFS images/<vmid>/ directories that have no Proxmox VM.

        Returns list of VMIDs removed. Safe to call only when no other template
        fetch/import operations are running (caller's responsibility).
        """
        images_dir = Path(self._settings.templates_dir) / "images"
        if not images_dir.exists():
            return []

        proxmox_vmids: set[int] = set()
        for node in self._client.get_nodes():
            if node.status != "online":
                continue
            for vm in self._client.get_vms(node.name):
                if TEMPLATE_VMID_MIN <= vm.vmid <= TEMPLATE_VMID_MAX:
                    proxmox_vmids.add(vm.vmid)

        removed = []
        for d in images_dir.iterdir():
            if not d.is_dir() or not d.name.isdigit():
                continue
            vmid = int(d.name)
            if TEMPLATE_VMID_MIN <= vmid <= TEMPLATE_VMID_MAX and vmid not in proxmox_vmids:
                shutil.rmtree(d)
                removed.append(vmid)
        return removed

    def delete(self, name: str) -> None:
        target = box_to_name(name) if "/" in name else name
        for t in self._collect():
            if t.name == target:
                self._client.delete_vm(t.node, t.vmid)
                return
        raise RuntimeError(f"template '{name}' not found")

    def fetch_vagrant(self, box: str, log_fn: Callable[[str], None] = print) -> int:
        """Download a Vagrant Cloud libvirt box, import it as a Proxmox template."""
        if "/" not in box:
            raise ValueError(
                f"invalid box name '{box}' — expected 'user/name' (e.g. generic-x64/debian12)"
            )

        tpl_name = box_to_name(box)

        if self.get_vmid(tpl_name) is not None:
            raise RuntimeError(
                f"template '{tpl_name}' already exists — "
                f"delete it first with: lab template delete {tpl_name}"
            )

        nodes = [n for n in self._client.get_nodes() if n.status == "online"]
        if not nodes:
            raise RuntimeError("no online Proxmox nodes available")
        node = nodes[0].name

        vmid, vm_dir, qcow2_path = self._allocate_slot()
        # Staged outside the VMID slot: a retry allocates a fresh VMID, so a
        # partial download parked in the old slot could never be resumed.
        box_path = Path(self._settings.templates_dir) / ".downloads" / f"{tpl_name}.box"

        log_fn(f"resolving {box} on Vagrant Cloud")
        url = _get_download_url(box)
        try:
            log_fn("downloading box")
            _download(url, box_path)
            log_fn("extracting qcow2")
            _extract_qcow2(box_path, qcow2_path)
        except Exception:
            # _all_vmids_in_range counts slot directories, so leaving one behind
            # burns the VMID until cleanup_orphaned_slots runs. The staged
            # download is deliberately left in place for the next attempt.
            log_fn(f"error: releasing VMID slot {vmid}")
            qcow2_path.unlink(missing_ok=True)
            try:
                vm_dir.rmdir()
            except OSError:
                pass
            raise
        box_path.unlink(missing_ok=True)

        # description stores the original box name (with /) for display in lab template list
        self._run_import(node, vmid, tpl_name, qcow2_path, log_fn, description=box)
        log_fn(f"template ready: {box}")
        return vmid

    def import_qcow2(self, name: str, source: Path, log_fn: Callable[[str], None] = print) -> int:
        """Import a local QCOW2/VMDK/raw disk as a Proxmox template.

        source must be a path accessible on the management VM.
        Returns the VMID of the created template.
        """
        if self.get_vmid(name) is not None:
            raise RuntimeError(
                f"template '{name}' already exists — "
                f"delete it first with: lab template delete {name}"
            )

        nodes = [n for n in self._client.get_nodes() if n.status == "online"]
        if not nodes:
            raise RuntimeError("no online Proxmox nodes available")
        node = nodes[0].name

        vmid, _, qcow2_path = self._allocate_slot()

        log_fn(f"copying disk to NFS storage ({source.stat().st_size // 1024 // 1024} MB)")
        shutil.copy2(source, qcow2_path)

        self._run_import(node, vmid, name, qcow2_path, log_fn, description=name)
        log_fn(f"template ready: {name}")
        return vmid

    def rename(self, old_name: str, new_name: str) -> None:
        """Rename a template. Updates both the Proxmox VM name and display name."""
        old_key = box_to_name(old_name) if "/" in old_name else old_name
        new_key = box_to_name(new_name) if "/" in new_name else new_name
        for t in self._collect():
            if t.name == old_key:
                self._client.rename_vm(t.node, t.vmid, new_key, description=new_name)
                return
        raise RuntimeError(f"template '{old_name}' not found")

