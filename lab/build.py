from __future__ import annotations

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
}


class BuildManager:
    def __init__(self, proxmox: ProxmoxClient, s: Settings) -> None:
        self._proxmox = proxmox
        self._s = s
        self._sources = BuildSourceManager(s.build_sources_dir)

    def build(
        self,
        build_name: str,
        version: str,
        url: str = "",
        log_fn: Callable[[str], None] = print,
    ) -> int:
        if build_name not in SUPPORTED_BUILDS:
            supported = ", ".join(SUPPORTED_BUILDS)
            raise ValueError(f"unknown build '{build_name}' — supported: {supported}")

        spec = SUPPORTED_BUILDS[build_name]
        script = SCRIPTS_DIR / spec["script"]
        if not script.exists():
            raise FileNotFoundError(f"build script not found: {script}")

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
