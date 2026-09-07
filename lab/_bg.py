"""Internal background task runner — not a user-facing command."""
from __future__ import annotations

import sys
from typing import Callable

from lab.ops import append_log, complete_operation, fail_operation, incomplete_operation, set_running
from lab.scheduler import InsufficientCapacityError


def _log(op_id: int, msg: str, level: str = "info") -> None:
    append_log(op_id, msg, level)


def _template_fetch(op_id: int, box: str) -> None:
    from lab.config import get_settings
    from lab.proxmox import ProxmoxClient
    from lab.templates import TemplateManager

    s = get_settings()
    mgr = TemplateManager(ProxmoxClient(s), s)
    mgr.fetch_vagrant(box, log_fn=lambda msg: _log(op_id, msg))


def _template_import(op_id: int, name: str, source: str) -> None:
    from pathlib import Path

    from lab.config import get_settings
    from lab.proxmox import ProxmoxClient
    from lab.templates import TemplateManager

    s = get_settings()
    mgr = TemplateManager(ProxmoxClient(s), s)
    mgr.import_qcow2(name, Path(source), log_fn=lambda msg: _log(op_id, msg))


def _template_source_add(op_id: int, build_name: str, source_path: str) -> None:
    from pathlib import Path

    from lab.build_sources import BuildSourceManager
    from lab.config import get_settings

    s = get_settings()
    mgr = BuildSourceManager(s.build_sources_dir)
    mgr.add(build_name, Path(source_path), log_fn=lambda msg: _log(op_id, msg))


def _template_build(
    op_id: int,
    build_name: str,
    version: str,
    url: str = "",
    skip_update: str = "0",
    skip_optimize: str = "0",
    source: str = "",
) -> None:
    from lab.build import BuildManager
    from lab.config import get_settings
    from lab.proxmox import ProxmoxClient

    s = get_settings()
    mgr = BuildManager(ProxmoxClient(s), s)
    mgr.build(
        build_name, version, url=url,
        log_fn=lambda msg: _log(op_id, msg),
        skip_update=skip_update == "1",
        skip_optimize=skip_optimize == "1",
        source=source,
    )


def _deploy_start(op_id: int, scenario_path: str, username: str, skip_ansible: str, target: str = "", no_headroom: str = "0") -> None:
    from lab.deploy import DeployEngine
    engine = DeployEngine()
    engine.start(
        scenario_path,
        username,
        skip_ansible=skip_ansible == "1",
        target=target or None,
        log_fn=lambda msg: _log(op_id, msg),
        no_headroom=no_headroom == "1",
    )


def _deploy_stop(op_id: int, deployment_name: str, username: str) -> None:
    from lab.deploy import DeployEngine
    engine = DeployEngine()
    engine.stop(
        deployment_name,
        username,
        log_fn=lambda msg: _log(op_id, msg),
    )


def _deploy_resume(op_id: int, deployment_name: str, username: str) -> None:
    from lab.deploy import DeployEngine
    engine = DeployEngine()
    engine.resume(
        deployment_name,
        username,
        log_fn=lambda msg: _log(op_id, msg),
    )


def _deploy_destroy(op_id: int, deployment_name: str, username: str, target: str = "", no_cascade: str = "0") -> None:
    from lab.deploy import DeployEngine
    engine = DeployEngine()
    engine.destroy(
        deployment_name,
        username,
        target=target or None,
        cascade=no_cascade != "1",
        log_fn=lambda msg: _log(op_id, msg),
    )



def _snapshot_create(op_id: int, deployment_name: str, username: str, vm: str = "") -> None:
    from lab.deploy import DeployEngine
    DeployEngine().snapshot_create(
        deployment_name, username, vm=vm or None, log_fn=lambda msg: _log(op_id, msg),
    )


def _snapshot_rollback(op_id: int, deployment_name: str, username: str, vm: str = "", all_flag: str = "0") -> None:
    from lab.deploy import DeployEngine
    DeployEngine().snapshot_rollback(
        deployment_name, username, vm=vm or None, all_vms=all_flag == "1",
        log_fn=lambda msg: _log(op_id, msg),
    )


def _snapshot_delete(op_id: int, deployment_name: str, username: str, vm: str = "") -> None:
    from lab.deploy import DeployEngine
    DeployEngine().snapshot_delete(
        deployment_name, username, vm=vm or None, log_fn=lambda msg: _log(op_id, msg),
    )


def _detonate(op_id: int, deployment_name: str, username: str,
              tactic: str = "", revert: str = "", settle: str = "90",
              per_technique: str = "0") -> None:
    from lab.deploy import DeployEngine
    DeployEngine().detonate(
        deployment_name, username, tactic=tactic, revert=revert,
        settle=int(settle or 90), per_technique=(per_technique == "1"),
        log_fn=lambda msg: _log(op_id, msg),
    )


def _ct_template_fetch(op_id: int, name: str) -> None:
    from lab.config import get_settings
    from lab.proxmox import ProxmoxClient

    s = get_settings()
    px = ProxmoxClient(s)
    nodes = [n for n in px.get_nodes() if n.status == "online"]
    if not nodes:
        raise RuntimeError("no online nodes found")
    _log(op_id, f"fetching {name} → nfs-templates...")
    try:
        px.fetch_ct_template(nodes[0].name, name)
    except FileExistsError:
        _log(op_id, f"already downloaded: {name}")
        return
    _log(op_id, "done")


def _noop(op_id: int) -> None:
    """No-op task used only by integration tests to verify background execution pipeline."""
    _log(op_id, "noop complete")


_TASKS: dict[str, Callable[..., None]] = {
    "template_fetch": _template_fetch,
    "template_import": _template_import,
    "template_source_add": _template_source_add,
    "template_build": _template_build,
    "ct_template_fetch": _ct_template_fetch,
    "deploy_start": _deploy_start,
    "deploy_stop": _deploy_stop,
    "deploy_resume": _deploy_resume,
    "deploy_destroy": _deploy_destroy,
    "snapshot_create": _snapshot_create,
    "snapshot_rollback": _snapshot_rollback,
    "snapshot_delete": _snapshot_delete,
    "detonate": _detonate,
    "_noop": _noop,
}


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: python -m lab._bg <op_id> <task> [args...]", file=sys.stderr)
        sys.exit(1)

    op_id = int(sys.argv[1])
    task = sys.argv[2]
    args = sys.argv[3:]

    if task not in _TASKS:
        _log(op_id, f"unknown task: {task}", "error")
        fail_operation(op_id)
        sys.exit(1)

    set_running(op_id)
    try:
        _TASKS[task](op_id, *args)
        complete_operation(op_id)
    except InsufficientCapacityError as exc:
        # Expected, handled outcome — the scheduler correctly refused to
        # oversubscribe a node, not a bug. Warn, don't error, and mark the
        # operation 'incomplete' rather than 'failed': nothing needs
        # investigating, the caller just needs more capacity or a smaller target.
        _log(op_id, str(exc), "warn")
        incomplete_operation(op_id)
        sys.exit(1)
    except Exception as exc:
        _log(op_id, str(exc), "error")
        fail_operation(op_id)
        sys.exit(1)


if __name__ == "__main__":
    main()
