from __future__ import annotations

import os
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
    },
}


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
    ) -> int:
        if build_name not in SUPPORTED_BUILDS:
            supported = ", ".join(SUPPORTED_BUILDS)
            raise ValueError(f"unknown build '{build_name}' — supported: {supported}")

        spec = SUPPORTED_BUILDS[build_name]
        script = SCRIPTS_DIR / spec["script"]
        if not script.exists():
            raise FileNotFoundError(f"build script not found: {script}")

        if spec.get("builder") == "proxmox":
            return self._build_proxmox(
                build_name, version, script, skip_update, skip_optimize, log_fn, dry_run
            )
        if dry_run:
            raise ValueError(f"--dry-run is not supported for '{build_name}'")

        # Image-source builds (cisco-iosvl2): the script takes a local disk-image path
        # and writes a fixed-name qcow2 into output_dir (via OUT_DIR), which we import.
        if spec.get("source_arg"):
            if not source:
                raise ValueError(f"'{build_name}' requires --source <path to disk image>")
            src = Path(source).expanduser().resolve()
            if not src.exists():
                raise FileNotFoundError(f"source image not found: {src}")
            out_dir = Path(spec["output_dir"])
            env = dict(os.environ)
            env["OUT_DIR"] = str(out_dir)
            log_fn(f"source: {src}")
            log_fn(f"running {script.name}")
            self._stream([str(script), str(src)], log_fn, env=env)
            output = out_dir / spec["output_file"]
            if not output.exists():
                raise RuntimeError(f"build completed but {output} was not produced")
            log_fn(f"output: {output}")
            tpl_name = f"{build_name}-{version}" if version else build_name
            return TemplateManager(self._proxmox, self._s).import_qcow2(
                tpl_name, output, log_fn=log_fn, disk=spec.get("disk_bus", "scsi0")
            )

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
