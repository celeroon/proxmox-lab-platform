from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from lab.build_sources import BuildSourceManager
from lab.config import Settings
from lab.proxmox import ProxmoxClient
from lab.templates import TemplateManager

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"

SUPPORTED_BUILDS: dict[str, dict] = {
    "nethsecurity": {
        "script": "build-nethsecurity.sh",
        "requires_source": False,
        "output_dir": "/var/lib/lab-platform/build-work/nethsecurity/tmp_out",
    },
    # Windows via rgl/windows-vagrant, built directly on a Proxmox node (proxmox-iso
    # builder). "version" is a variant selector (11 | 2025); the produced template is
    # windows-<variant>. builder="proxmox" skips the qcow2/import path — the script
    # creates the template on the node itself.
    "windows": {
        "script": "build-windows.sh",
        "requires_source": False,
        "builder": "proxmox",
    },
    # Cisco IOSvL2 switch: clones the packer repo, boots the extracted virtioa.qcow2,
    # configures it over serial, and produces a version-less cisco-iosvl2.qcow2 which
    # is then imported. The disk image is supplied by the caller (--source); nothing
    # is downloaded. source_arg=True means the script's only argument is that path.
    "cisco-iosvl2": {
        "script": "build-cisco-iosvl2.sh",
        "requires_source": False,
        "source_arg": True,
        "output_dir": "/var/lib/lab-platform/build-work/cisco-iosvl2-out",
        "output_file": "cisco-iosvl2.qcow2",
        # IOSvL2 can't see a virtio-SCSI disk as flash0: — import on virtio-blk.
        "disk_bus": "virtio0",
        "min_free_gb": 6,
    },
    # Cisco Catalyst 8000v router (IOS-XE): same --source flow as cisco-iosvl2 — clones
    # the packer repo, boots the supplied qcow2, configures it over serial, and produces
    # a version-less cisco-8kv.qcow2 which is then imported. IOS-XE is Linux-based, so the
    # default virtio-SCSI import works (no flash0: quirk like the switch).
    "cisco-8kv": {
        "script": "build-cisco-8kv.sh",
        "requires_source": False,
        "source_arg": True,
        "output_dir": "/var/lib/lab-platform/build-work/cisco-8kv-out",
        "output_file": "cisco-8kv.qcow2",
        "min_free_gb": 10,
    },
    # Cisco Secure Firewall Threat Defense Virtual (FTDv). Same --source flow: clones the
    # packer repo, boots the supplied qcow2, runs the setup wizard, and produces an
    # UNREGISTERED configured qcow2 (registration to FMC is a post-deploy step). single_use
    # marks each imported template so it can never be cloned by more than one deployment —
    # FTDv is a pet registered to FMC, not cattle. Auto-numbered pool (cisco-ftd-1, -2, …).
    "cisco-ftd": {
        "script": "build-cisco-ftd.sh",
        "requires_source": False,
        "source_arg": True,
        "single_use": True,
        "output_dir": "/var/lib/lab-platform/build-work/cisco-ftd-out",
        "output_file": "cisco-ftd.qcow2",
        "min_free_gb": 20,
    },
    # Cisco Secure Firewall Management Center Virtual (FMCv). Same single-use pet model as
    # cisco-ftd (registers to Cisco SSM). Heavier build: 32 GB RAM, ~40m boot.
    "cisco-fmc": {
        "script": "build-cisco-fmc.sh",
        "requires_source": False,
        "source_arg": True,
        "single_use": True,
        "output_dir": "/var/lib/lab-platform/build-work/cisco-fmc-out",
        "output_file": "cisco-fmc.qcow2",
        # FMCv firstboot populates its DB and the working qcow2 grows to tens of GB; a full
        # disk pauses the build VM mid-boot (QEMU werror=stop). Require real headroom.
        "min_free_gb": 60,
    },
}

# Proxmox tag stamped on single_use templates; the deploy engine keys the one-deployment
# claim off this tag (see lab/deploy.py). The marker lives on the template, not scenario.yml.
SINGLE_USE_TAG = "single-use"


def is_single_use_build(build_name: str) -> bool:
    return bool(SUPPORTED_BUILDS.get(build_name, {}).get("single_use"))


def _free_gb(path: Path) -> float:
    """Free space (GB) on the filesystem holding path, walking up to an existing ancestor
    (the build/output dir may not exist yet)."""
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(p).free / (1024 ** 3)


class BuildManager:
    def __init__(self, proxmox: ProxmoxClient, s: Settings) -> None:
        self._proxmox = proxmox
        self._s = s
        self._sources = BuildSourceManager(s.build_sources_dir)

    @staticmethod
    def _stream(cmd: list[str], log_fn: Callable[[str], None], env: dict | None = None) -> None:
        """Run cmd, streaming combined stdout/stderr to log_fn; raise on non-zero exit."""
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env
        )
        for line in proc.stdout:
            log_fn(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError(f"{Path(cmd[0]).name} failed (exit {proc.returncode})")

    def build(
        self,
        build_name: str,
        version: str,
        url: str = "",
        log_fn: Callable[[str], None] = print,
        skip_update: bool = False,
        skip_optimize: bool = False,
        dry_run: bool = False,
        source: str = "",
        count: int = 1,
        gui: bool = False,
    ) -> int:
        if build_name not in SUPPORTED_BUILDS:
            supported = ", ".join(SUPPORTED_BUILDS)
            raise ValueError(f"unknown build '{build_name}' — supported: {supported}")

        spec = SUPPORTED_BUILDS[build_name]
        script = SCRIPTS_DIR / spec["script"]
        if not script.exists():
            raise FileNotFoundError(f"build script not found: {script}")

        if count != 1 and not spec.get("single_use"):
            raise ValueError(f"--count is only supported for single-use builds (cisco-ftd, cisco-fmc), not '{build_name}'")
        if count < 1:
            raise ValueError(f"--count must be >= 1, got {count}")

        if spec.get("builder") == "proxmox":
            return self._build_proxmox(
                build_name, version, script, skip_update, skip_optimize, log_fn, dry_run
            )
        if dry_run:
            raise ValueError(f"--dry-run is not supported for '{build_name}'")

        # Image-source builds (cisco-iosvl2 / cisco-8kv / cisco-ftd / cisco-fmc): the script
        # takes a local disk-image path and writes a fixed-name qcow2 into output_dir (via
        # OUT_DIR), which we import.
        if spec.get("source_arg"):
            if not source:
                raise ValueError(f"'{build_name}' requires --source <path to disk image>")
            src = Path(source).expanduser().resolve()
            if not src.exists():
                raise FileNotFoundError(f"source image not found: {src}")
            tmgr = TemplateManager(self._proxmox, self._s)

            # single_use builds are an auto-numbered pool (cisco-ftd-1, -2, …): each build
            # boots the source fresh so every template is its own first boot, and a later
            # run continues past the highest existing number. Non-pool builds keep the
            # historical single-template name (build_name-version, or build_name).
            single_use = bool(spec.get("single_use"))
            if single_use:
                start = tmgr.next_pool_index(build_name)
                tpl_names = [f"{build_name}-{start + i}" for i in range(count)]
            else:
                tpl_names = [f"{build_name}-{version}" if version else build_name]

            out_dir = Path(spec["output_dir"])
            env = dict(os.environ)
            env["OUT_DIR"] = str(out_dir)
            if gui:
                # Turn off headless in the packer build so the QEMU window opens (test/watch).
                env["GUI"] = "1"
            log_fn(f"source: {src}")

            # Fail fast if the build volume can't hold this appliance's transient disk. FMCv
            # firstboot alone grows the working qcow2 to tens of GB — without this the build
            # runs ~40 min then QEMU pauses on ENOSPC mid-boot. Checked per iteration since a
            # --count pool accumulates imported templates on the same filesystem.
            min_free = spec.get("min_free_gb")

            last_vmid = 0
            for tpl_name in tpl_names:
                if min_free:
                    free = _free_gb(out_dir)
                    if free < min_free:
                        raise RuntimeError(
                            f"not enough disk space to build '{build_name}': need ~{min_free} GB "
                            f"free on {out_dir}'s filesystem, have {free:.0f} GB — free space or "
                            f"grow the volume before building (a full disk pauses the build VM "
                            f"mid-boot)"
                        )
                    log_fn(f"disk check: {free:.0f} GB free on build volume (need >= {min_free} GB) — OK")
                log_fn(f"=== building {tpl_name} ===")
                log_fn(f"running {script.name}")
                self._stream([str(script), str(src)], log_fn, env=env)
                output = out_dir / spec["output_file"]
                if not output.exists():
                    raise RuntimeError(f"build completed but {output} was not produced")
                log_fn(f"output: {output}")
                last_vmid = tmgr.import_qcow2(
                    tpl_name, output, log_fn=log_fn, disk=spec.get("disk_bus", "scsi0"),
                    tags=SINGLE_USE_TAG if single_use else "",
                    protection=single_use,
                )
            return last_vmid

        cmd = [str(script), version]
        if spec["requires_source"]:
            source_path = self._sources.get_path(build_name)
            cmd.append(str(source_path))
            log_fn(f"source: {source_path}")
        elif url:
            cmd.append(url)

        log_fn(f"running {script.name}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            log_fn(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError(f"build script failed (exit {proc.returncode})")

        output_dir = Path(spec["output_dir"])
        outputs = sorted(output_dir.glob("*.qcow2"))
        if not outputs:
            raise RuntimeError(f"build completed but no qcow2 found in {output_dir}")
        output = outputs[0]
        log_fn(f"output: {output}")

        tpl_name = f"{build_name}-{version}" if version else build_name
        mgr = TemplateManager(self._proxmox, self._s)
        return mgr.import_qcow2(tpl_name, output, log_fn=log_fn)

    def _build_proxmox(
        self,
        build_name: str,
        version: str,
        script: Path,
        skip_update: bool,
        skip_optimize: bool,
        log_fn: Callable[[str], None],
        dry_run: bool = False,
    ) -> int:
        """Build a template directly on a Proxmox node (no qcow2/import).

        The script creates the template on the node as windows-<version> in the
        9000-9999 range; we just resolve its VMID afterwards. Errors early if a
        template of that name already exists. dry_run prints the detected values
        and patched config and builds nothing.
        """
        tpl_name = f"{build_name}-{version}" if version else build_name  # windows-11
        mgr = TemplateManager(self._proxmox, self._s)
        if not dry_run and mgr.get_vmid(tpl_name) is not None:
            raise RuntimeError(
                f"template '{tpl_name}' already exists — delete it first with: "
                f"lab template delete {tpl_name}"
            )

        env = dict(os.environ)
        env["SKIP_UPDATE"] = "1" if skip_update else "0"
        env["SKIP_OPTIMIZE"] = "1" if skip_optimize else "0"
        env["WIN_TEMPLATE_NAME"] = tpl_name
        if dry_run:
            env["DRY_RUN"] = "1"

        if not dry_run:
            log_fn(
                f"building {tpl_name} on Proxmox "
                f"(updates={'off' if skip_update else 'on'}, optimize={'off' if skip_optimize else 'on'})"
            )
        proc = subprocess.Popen(
            [str(script), version],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        for line in proc.stdout:
            log_fn(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError(f"windows build failed (exit {proc.returncode})")

        if dry_run:
            return 0

        vmid = mgr.get_vmid(tpl_name)
        if vmid is None:
            raise RuntimeError(
                f"build finished but template '{tpl_name}' was not found on Proxmox"
            )
        log_fn(f"template ready: {tpl_name} (VMID {vmid})")
        return vmid
