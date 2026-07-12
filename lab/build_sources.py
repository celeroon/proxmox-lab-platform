from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

_SUPPORTED_SUFFIXES = (".qcow2", ".img", ".vmdk", ".iso")

# expected qemu-img format string per file suffix
_EXPECTED_FORMATS: dict[str, str] = {
    ".qcow2": "qcow2",
    ".vmdk": "vmdk",
    # .img and .iso have no fixed format — accept any qemu-img-readable file
}


def _validate_disk_image(path: Path) -> None:
    """Raise ValueError if qemu-img cannot read the file or format doesn't match suffix."""
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ValueError(
            f"not a valid disk image — qemu-img: {result.stderr.strip()}"
        )
    try:
        info = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ValueError("could not parse qemu-img output")

    expected = _EXPECTED_FORMATS.get(path.suffix.lower())
    if expected and info.get("format") != expected:
        raise ValueError(
            f"file format is '{info.get('format')}', expected '{expected}' for {path.suffix} files"
        )


class BuildSourceManager:
    def __init__(self, sources_dir: str) -> None:
        self._dir = Path(sources_dir)

    def add(self, build_name: str, source: Path, log_fn: Callable[[str], None] = print) -> Path:
        if not source.exists():
            raise FileNotFoundError(f"file not found: {source}")
        suffix = source.suffix.lower()
        if suffix not in _SUPPORTED_SUFFIXES:
            raise ValueError(
                f"unsupported file type '{suffix}' — expected: {', '.join(_SUPPORTED_SUFFIXES)}"
            )
        dest = self._dir / f"{build_name}{suffix}"
        if dest.exists():
            raise FileExistsError(
                f"source '{dest.name}' already staged — "
                f"delete it first: lab template source delete {dest.name}"
            )
        log_fn("validating disk image")
        _validate_disk_image(source)
        size_mb = source.stat().st_size // 1_048_576
        log_fn(f"copying {source.name} ({size_mb} MB) → {dest}")
        shutil.copy2(source, dest)
        log_fn(f"staged: {dest.name}")
        return dest

    def list(self) -> list[dict]:
        if not self._dir.exists():
            return []
        return [
            {"name": f.name, "size": f.stat().st_size}
            for f in sorted(self._dir.iterdir())
            if f.is_file()
        ]

    def delete(self, name: str) -> None:
        target = self._dir / name
        if not target.exists():
            raise FileNotFoundError(f"source file not found: {name}")
        target.unlink()

    def get_path(self, build_name: str) -> Path:
        for suffix in _SUPPORTED_SUFFIXES:
            p = self._dir / f"{build_name}{suffix}"
            if p.exists():
                return p
        raise FileNotFoundError(
            f"no source file for '{build_name}' in {self._dir} — "
            f"run: lab template source add {build_name} <file>"
        )
