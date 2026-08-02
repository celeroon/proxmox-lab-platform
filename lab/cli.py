import sys
import time
from pathlib import Path

import typer

from lab.config import Settings, get_settings, require_proxmox
from lab.ops import (
    append_log, cancel_operation, create_operation, current_username, format_duration,
    get_logs, get_operation, is_admin, list_operations, spawn_background,
)
from lab.proxmox import ProxmoxClient
from lab.templates import TemplateManager

_PROJECT_ROOT = Path(__file__).parent.parent

app = typer.Typer(no_args_is_help=True)

# Computed once at CLI startup — reflects whoever is running this process. Used to
# hide admin-only commands/groups from non-admins' --help output entirely (on top of
# the is_admin() checks inside each command body, which still enforce this even if
# someone runs a hidden command directly by name).
_caller_is_admin = is_admin()

template_app = typer.Typer(no_args_is_help=True, help="Manage Proxmox templates.")
source_app   = typer.Typer(no_args_is_help=True, help="Manage vendor source files for template building.")
ct_app       = typer.Typer(no_args_is_help=True, help="Manage LXC container templates.")
deploy_app   = typer.Typer(no_args_is_help=True, help="Deploy, stop, and destroy scenario deployments.")
user_app     = typer.Typer(no_args_is_help=True, help="Manage platform users.")
ops_app         = typer.Typer(no_args_is_help=True, help="View background operation history and logs.")

app.add_typer(template_app,    name="template", hidden=not _caller_is_admin)
template_app.add_typer(source_app, name="source", hidden=not _caller_is_admin)
template_app.add_typer(ct_app,     name="ct", hidden=not _caller_is_admin)
app.add_typer(deploy_app,      name="deploy")
app.add_typer(user_app,        name="user", hidden=not _caller_is_admin)
app.add_typer(ops_app,         name="ops", hidden=not _caller_is_admin)


# ── status helpers ────────────────────────────────────────────────────────────

def _bar(pct: float, width: int = 20) -> str:
    filled = round(max(0.0, min(1.0, pct)) * width)
    return '█' * filled + '░' * (width - filled)


def _fmt_gb(b: int) -> str:
    gb = b / 1_073_741_824
    return f"{gb / 1024:.1f} TB" if gb >= 1024 else f"{gb:.1f} GB"


def _fmt_speed(mbps: float) -> str:
    """Network throughput formatter — bits-based (Mb/s / Gb/s)."""
    if mbps >= 1000:
        return f"{mbps / 1000:.2f} Gb/s"
    return f"{mbps:.1f} Mb/s"


def _fmt_bytes_speed(mbs: float) -> str:
    """Storage throughput formatter — bytes-based (MB/s / GB/s)."""
    if mbs >= 1000:
        return f"{mbs / 1000:.2f} GB/s"
    return f"{mbs:.1f} MB/s"


def _count_guests_per_node(resources: list[dict]) -> dict[str, dict[str, int]]:
    """Tally running/total VM and CT counts per node from a cluster/resources?type=vm
    response. Excludes templates — they're not running instances."""
    counts: dict[str, dict[str, int]] = {}
    for r in resources:
        if r.get("template"):
            continue
        node = r.get("node", "")
        c = counts.setdefault(node, {"vm_running": 0, "vm_total": 0, "ct_running": 0, "ct_total": 0})
        is_ct = r.get("type", "qemu") == "lxc"
        running = r.get("status") == "running"
        if is_ct:
            c["ct_total"] += 1
            c["ct_running"] += int(running)
        else:
            c["vm_total"] += 1
            c["vm_running"] += int(running)
    return counts


_PAGE_SIZE = 10


def _getch() -> str:
    """Read one raw keypress from stdin. Returns '' if stdin is not a TTY."""
    import termios, tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _pager_prompt(shown: int, total: int) -> bool:
    """Print a pager hint and wait for SPACE (continue) or Q/anything else (quit).
    Returns True to continue, False to stop. Skips interaction when not a TTY."""
    if not sys.stdout.isatty():
        return True
    remaining = total - shown
    sys.stdout.write(
        f"\n  \033[2m— {shown}/{total} shown · SPACE {remaining} more · Q quit —\033[0m  "
    )
    sys.stdout.flush()
    ch = _getch()
    sys.stdout.write("\r\033[K")   # erase the prompt line
    sys.stdout.flush()
    return ch == " "



# ── status ────────────────────────────────────────────────────────────────────

@app.command(hidden=not _caller_is_admin)
def status(
    interval: int = typer.Option(5, "--interval", "-n", help="Refresh interval in seconds."),
):
    """Live cluster status — nodes, deployments, SDN. Ctrl+C to exit (admin only)."""
    if not is_admin():
        typer.echo("error: lab status requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    import datetime
    from rich.console import Console
    from rich.live import Live
    from rich.text import Text
    from lab.db import get_conn as _get_conn

    s = get_settings()
    require_proxmox(s)
    px = ProxmoxClient(s)
    console = Console()

    def _build() -> Text:
        t = Text()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        nodes = sorted(px.get_nodes(), key=lambda n: n.name)  # stable order — Proxmox's /nodes API doesn't guarantee one

        online = [n for n in nodes if n.status == "online"]
        cluster_label = "single node" if len(nodes) == 1 else f"{len(nodes)} nodes"

        try:
            guest_counts = _count_guests_per_node(px.get_cluster_resources("vm"))
        except Exception:
            guest_counts = {}

        t.append("Lab Platform", style="bold")
        t.append(f" — {cluster_label}   {now}   ")
        t.append("[Ctrl+C to quit]\n", style="dim")

        # Detect shared storage pool once (used in cluster section)
        shared_pool = None
        storage_name = s.proxmox_storage or None
        try:
            storage_list = px.get_storage()
            candidate = None
            if storage_name:
                candidate = next((p for p in storage_list if p.name == storage_name), None)
            else:
                for ptype in ('rbd', 'zfspool', 'lvmthin'):
                    candidate = next((p for p in storage_list if p.type == ptype), None)
                    if candidate:
                        break
                if candidate is None and storage_list:
                    candidate = storage_list[0]
            if candidate and candidate.shared:
                if candidate.type == "rbd" and online:
                    # Global /storage inflates Ceph by node count; use one node's view.
                    try:
                        node_pools = px.get_node_storage(online[0].name)
                        node_pool = next((p for p in node_pools if p.name == candidate.name), None)
                        shared_pool = node_pool if (node_pool and node_pool.total > 0) else candidate
                    except Exception:
                        shared_pool = candidate
                else:
                    shared_pool = candidate
        except Exception:
            pass

        # ── per-node ──
        for node in nodes:
            t.append(f"\nNODE {node.name}  ", style="bold")
            t.append("online\n" if node.status == "online" else f"{node.status}\n",
                     style="green" if node.status == "online" else "red")

            if node.status != "online":
                continue

            # CPU
            cpu_pct = node.cpu_usage
            cores_str = f"   {node.cpu_total} cores" if node.cpu_total else ""
            t.append(f"  CPU  [{_bar(cpu_pct)}]  {cpu_pct * 100:.0f}%{cores_str}\n")

            # RAM
            used_ram = node.total_ram - node.free_ram
            ram_pct = used_ram / node.total_ram if node.total_ram > 0 else 0.0
            t.append(f"  RAM  [{_bar(ram_pct)}]  {_fmt_gb(used_ram)} / {_fmt_gb(node.total_ram)}\n")

            # DISK — skip per-node when shared Ceph pool is present (shown in cluster section)
            if not (shared_pool and shared_pool.type == "rbd"):
                try:
                    node_pools = px.get_node_storage(node.name)
                    pool = None
                    if storage_name:
                        pool = next((p for p in node_pools if p.name == storage_name), None)
                    if pool is None:
                        for ptype in ('rbd', 'zfspool', 'lvmthin'):
                            pool = next((p for p in node_pools if p.type == ptype), None)
                            if pool:
                                break
                        if pool is None and node_pools:
                            pool = node_pools[0]
                    if pool and pool.total > 0:
                        used_disk = pool.total - pool.free
                        disk_pct = used_disk / pool.total
                        t.append(f"  DISK [{_bar(disk_pct)}]  {_fmt_gb(used_disk)} / {_fmt_gb(pool.total)}  ({pool.name})\n")
                except Exception:
                    pass

            # NET — 1 min average throughput in Mb/s (megabits)
            try:
                rrd = px.get_node_rrddata(node.name)
                rx = rrd['netin']  * 8 / 1_000_000
                tx = rrd['netout'] * 8 / 1_000_000
                t.append(f"  NET   ↓ {_fmt_speed(rx)}   ↑ {_fmt_speed(tx)}\n")
            except Exception:
                pass

            # VMs/CTs running on this node
            gc = guest_counts.get(node.name)
            if gc:
                t.append(
                    f"  VMs   {gc['vm_running']} running / {gc['vm_total']} total"
                    f"     CTs   {gc['ct_running']} running / {gc['ct_total']} total\n"
                )

        # ── cluster totals (only if > 1 online node) ──
        if len(online) > 1:
            total_ram = sum(n.total_ram for n in online)
            used_ram_total = sum(n.total_ram - n.free_ram for n in online)
            avg_cpu = sum(n.cpu_usage for n in online) / len(online)
            total_cores = sum(n.cpu_total for n in online)
            ram_pct = used_ram_total / total_ram if total_ram > 0 else 0.0

            t.append(f"\nCLUSTER  {len(online)} nodes online  " + "─" * 44 + "\n", style="bold")
            cores_str = f"   {total_cores} cores total" if total_cores else ""
            t.append(f"  CPU  [{_bar(avg_cpu)}]  {avg_cpu * 100:.0f}% avg{cores_str}\n")
            t.append(f"  RAM  [{_bar(ram_pct)}]  {_fmt_gb(used_ram_total)} / {_fmt_gb(total_ram)}\n")
            if shared_pool and shared_pool.total > 0:
                used = shared_pool.total - shared_pool.free
                t.append(f"  DISK [{_bar(used / shared_pool.total)}]  {_fmt_gb(used)} / {_fmt_gb(shared_pool.total)}  ({shared_pool.name})\n")
            if shared_pool and shared_pool.type == "rbd":
                try:
                    ceph = px.get_ceph_io(online[0].name)
                    if ceph:
                        t.append(
                            f"  CEPH  r {_fmt_bytes_speed(ceph['read_mbps'])}  {ceph['read_iops']} IOPS"
                            f"   w {_fmt_bytes_speed(ceph['write_mbps'])}  {ceph['write_iops']} IOPS\n"
                        )
                except Exception:
                    pass
            if guest_counts:
                vm_running = sum(c["vm_running"] for c in guest_counts.values())
                vm_total = sum(c["vm_total"] for c in guest_counts.values())
                ct_running = sum(c["ct_running"] for c in guest_counts.values())
                ct_total = sum(c["ct_total"] for c in guest_counts.values())
                t.append(
                    f"  VMs   {vm_running} running / {vm_total} total"
                    f"     CTs   {ct_running} running / {ct_total} total\n"
                )

        # ── deployments ──
        try:
            with _get_conn() as conn:
                with conn.cursor() as cur:
                    if is_admin():
                        cur.execute("""
                            SELECT d.name, d.status,
                                   COUNT(DISTINCT CASE WHEN v.type = 'vm'        THEN v.id END) AS vm_count,
                                   COUNT(DISTINCT CASE WHEN v.type = 'container' THEN v.id END) AS ct_count,
                                   COUNT(DISTINCT n.id)                                          AS net_count
                            FROM deployments d
                            LEFT JOIN vms v      ON v.deployment_id = d.id
                            LEFT JOIN networks n ON n.deployment_id = d.id
                            WHERE d.status IN ('active', 'deploying', 'stopped', 'failed')
                            GROUP BY d.id, d.name, d.status
                            ORDER BY d.created_at DESC
                        """)
                    else:
                        cur.execute("""
                            SELECT d.name, d.status,
                                   COUNT(DISTINCT CASE WHEN v.type = 'vm'        THEN v.id END) AS vm_count,
                                   COUNT(DISTINCT CASE WHEN v.type = 'container' THEN v.id END) AS ct_count,
                                   COUNT(DISTINCT n.id)                                          AS net_count
                            FROM deployments d
                            JOIN users u         ON u.id = d.user_id
                            LEFT JOIN vms v      ON v.deployment_id = d.id
                            LEFT JOIN networks n ON n.deployment_id = d.id
                            WHERE d.status IN ('active', 'deploying', 'stopped', 'failed') AND u.username = %s
                            GROUP BY d.id, d.name, d.status
                            ORDER BY d.created_at DESC
                        """, (current_username(),))
                    dep_rows = cur.fetchall()

            t.append("\nDEPLOYMENTS " + "─" * 54 + "\n", style="bold")
            if dep_rows:
                for row in dep_rows:
                    dep_status = row['status']
                    style = "green" if dep_status == "active" else "yellow" if dep_status in ("deploying", "stopped") else "red"
                    t.append(f"  {row['name']:<40}  VMs: {row['vm_count'] or 0:<4} CTs: {row['ct_count'] or 0:<4} Nets: {row['net_count'] or 0:<2}  ")
                    t.append(dep_status + "\n", style=style)
            else:
                t.append("  no active deployments\n", style="dim")
        except Exception as exc:
            t.append(f"\n  (deployment data unavailable: {exc})\n", style="dim")

        # ── SDN summary ──
        try:
            vnets = px.list_vnets()
            scenario_vnets = [v for v in vnets if v.get('vnet', '').startswith('v')]
            with _get_conn() as _conn:
                with _conn.cursor() as _cur:
                    _cur.execute("""
                        SELECT COUNT(CASE WHEN type = 'vm'        THEN 1 END) AS vm_count,
                               COUNT(CASE WHEN type = 'container' THEN 1 END) AS ct_count
                        FROM vms
                        WHERE deployment_id IN (
                            SELECT id FROM deployments
                            WHERE status IN ('active', 'deploying', 'stopped', 'failed')
                        )
                    """)
                    _row = _cur.fetchone()
            total_vms = _row['vm_count'] or 0
            total_cts = _row['ct_count'] or 0
            t.append(f"\nSDN  Zone: labzone (vxlan)  VNets: {len(scenario_vnets)} active   VMs: {total_vms}   CTs: {total_cts}\n")
        except Exception:
            pass

        t.append(f"\n  (1 min avg · refreshes every {interval}s)\n", style="dim")
        return t

    _last: list[Text] = []

    def _safe_build() -> Text:
        for attempt in range(2):
            try:
                frame = _build()
                _last[:] = [frame]
                return frame
            except Exception:
                if attempt == 0:
                    time.sleep(1)
        return _last[0] if _last else Text("connecting...\n", style="dim")

    try:
        with Live(console=console, refresh_per_second=4, screen=True) as live:
            while True:
                live.update(_safe_build())
                time.sleep(interval)
    except KeyboardInterrupt:
        pass


# ── console ───────────────────────────────────────────────────────────────────

@app.command()
def console(
    deployment: str = typer.Argument(..., help="Deployment name."),
    user: str = typer.Option("", "--user", help="Target username (admin only)."),
):
    """Show noVNC console URLs for all running VMs in a deployment."""
    from lab.db import get_conn as _get_conn

    if user and not is_admin():
        typer.echo("error: --user is only available to admin", err=True)
        raise typer.Exit(1)

    s = get_settings()

    if not s.web_url:
        typer.echo("error: WEB_URL is not set in .env — re-run setup.sh", err=True)
        raise typer.Exit(1)

    effective_user = user if user else current_username()

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT d.id FROM deployments d
                JOIN users u ON u.id = d.user_id
                WHERE d.name = %s AND u.username = %s AND d.status != 'destroyed'
                ORDER BY d.created_at DESC LIMIT 1
                """,
                (deployment, effective_user),
            )
            dep = cur.fetchone()

    if not dep:
        typer.echo(f"error: deployment '{deployment}' not found for user '{effective_user}'", err=True)
        if is_admin():
            with _get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM users WHERE username = %s", (effective_user,))
                    u = cur.fetchone()
                    if not u:
                        typer.echo(f"  (user '{effective_user}' does not exist in the database)", err=True)
                    else:
                        cur.execute(
                            "SELECT name, status, created_at FROM deployments WHERE user_id = %s AND status != 'destroyed' ORDER BY created_at DESC",
                            (u["id"],),
                        )
                        all_deps = cur.fetchall()
                        if not all_deps:
                            typer.echo(f"  (user '{effective_user}' has no active deployments)", err=True)
                        else:
                            typer.echo(f"  active deployments for '{effective_user}':", err=True)
                            for d in all_deps:
                                typer.echo(f"    {d['name']:<24}  status={d['status']}  created={d['created_at']}", err=True)
        raise typer.Exit(1)

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, vmid, node, status FROM vms WHERE deployment_id=%s ORDER BY vmid",
                (dep["id"],),
            )
            vms = cur.fetchall()

    if not vms:
        typer.echo("(no VMs in this deployment)")
        return

    from lab.tokens import create_token

    novnc_base = s.web_url.rstrip("/")

    typer.echo("")
    total = len(vms)
    for i, vm in enumerate(vms):
        if vm["status"] != "running":
            typer.echo(f"  {vm['name']:<16}  (not running — {vm['status']})")
        else:
            token = create_token(vm["vmid"], vm["node"])
            url = f"{novnc_base}/console/redirect?token={token}"
            typer.echo(f"  {vm['name']:<16}  {url}")
        shown = i + 1
        if shown < total and shown % _PAGE_SIZE == 0:
            if not _pager_prompt(shown, total):
                typer.echo(f"\n  (stopped at {shown}/{total})\n")
                return
    typer.echo("")


def _vm_connection_from_scenario(scenario_dict: dict, vm_name: str) -> dict:
    """Find the ansible.connection block for vm_name in a deployment's stored
    scenario dict. Handles both a standalone VM (exact name match) and a
    replica instance (base name + '-NN' from a count: N entry)."""
    import re

    vm_prefix = scenario_dict.get("vm_prefix", "")
    for v in scenario_dict.get("vms") or []:
        base_name = f"{vm_prefix}{v['name']}" if vm_prefix else v["name"]
        if vm_name == base_name:
            return (v.get("ansible") or {}).get("connection", {})
        if v.get("count", 1) >= 2 and re.fullmatch(rf"{re.escape(base_name)}-\d+", vm_name):
            return (v.get("ansible") or {}).get("connection", {})
    return {}


# ── ssh ───────────────────────────────────────────────────────────────────────

@app.command()
def ssh(
    name: str = typer.Argument(..., help="VM/CT name to SSH into (e.g. mgmt-1, agent-batch-1-56)."),
    user: str = typer.Option("", "--user", help="Target username (admin only)."),
    deployment: str = typer.Option("", "--deployment", help="Disambiguate if the name exists in more than one deployment."),
):
    """SSH into a VM/CT by name, using its scenario-defined credentials.

    Host key checking is disabled (StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null) —
    IPs get reused across this platform's deploy/destroy cycles, so a stale known_hosts
    entry from a previous, different VM would otherwise block every connection.
    """
    import os

    from lab.db import get_conn as _get_conn

    effective_user = _resolve_deploy_user(user)

    query = """
        SELECT v.vmid, v.management_ip, d.name AS deployment_name, d.scenario
        FROM vms v
        JOIN deployments d ON d.id = v.deployment_id
        JOIN users u ON u.id = d.user_id
        WHERE u.username = %s AND v.name = %s AND d.status != 'destroyed'
    """
    params: list = [effective_user, name]
    if deployment:
        query += " AND d.name = %s"
        params.append(deployment)

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()

    if not rows:
        typer.echo(f"error: no VM/CT named '{name}' found in any of {effective_user}'s deployments", err=True)
        raise typer.Exit(1)
    if len(rows) > 1:
        typer.echo(f"error: '{name}' exists in multiple deployments — disambiguate with --deployment:", err=True)
        for r in rows:
            typer.echo(f"  {r['deployment_name']}", err=True)
        raise typer.Exit(1)

    row = rows[0]
    if not row["management_ip"]:
        typer.echo(f"error: '{name}' has no management IP recorded", err=True)
        raise typer.Exit(1)

    conn_info = _vm_connection_from_scenario(row["scenario"] or {}, name)
    conn_type = conn_info.get("type", "ssh")
    if conn_type != "ssh":
        typer.echo(
            f"error: '{name}' uses connection type '{conn_type}', not ssh — "
            f"try 'lab console {row['deployment_name']}' instead",
            err=True,
        )
        raise typer.Exit(1)

    ssh_user = conn_info.get("user") or "root"
    password = conn_info.get("password", "")
    ip = row["management_ip"]

    typer.echo(f"connecting to {ssh_user}@{ip} (VMID {row['vmid']})")

    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    if password:
        try:
            os.execvp("sshpass", ["sshpass", "-p", password, "ssh", *ssh_opts, f"{ssh_user}@{ip}"])
        except FileNotFoundError:
            # sshpass not installed on the management VM — fall back to a manual
            # prompt rather than blocking the command entirely over an optional tool.
            typer.echo(f"(sshpass not installed — password: {password})")

    os.execvp("ssh", ["ssh", *ssh_opts, f"{ssh_user}@{ip}"])


# ── template ──────────────────────────────────────────────────────────────────

@template_app.command("fetch", hidden=not _caller_is_admin)
def template_fetch(box: str = typer.Argument(..., help="Vagrant Cloud box (e.g. generic-x64/debian12).")):
    """Download a Vagrant Cloud box, extract qcow2, import as a Proxmox template (background)."""
    if not is_admin():
        typer.echo("error: lab template fetch requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)
    command = " ".join(sys.argv)
    op_id = create_operation("template_fetch", command, current_username(), box)
    spawn_background(op_id, "template_fetch", box)
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


@template_app.command("list", hidden=not _caller_is_admin)
def template_list():
    """List available Proxmox templates (admin only)."""
    if not is_admin():
        typer.echo("error: lab template list requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)
    mgr = TemplateManager(ProxmoxClient(s), s)
    templates = mgr.list()
    if not templates:
        typer.echo("no templates found")
        return
    for t in sorted(templates, key=lambda t: t.description or t.name):
        typer.echo(f"  {t.description or t.name}")


@template_app.command("import", hidden=not _caller_is_admin)
def template_import(
    file: str = typer.Argument(..., help="Path to QCOW2, VMDK, or raw disk image."),
    name: str = typer.Argument(default="", help="Template name (default: derived from filename)."),
):
    """Import a local disk image as a Proxmox template (background)."""
    if not is_admin():
        typer.echo("error: lab template import requires admin", err=True)
        raise typer.Exit(1)
    source = Path(file).resolve()
    if not source.exists():
        typer.echo(f"error: file not found: {file}", err=True)
        raise typer.Exit(1)
    tpl_name = name or source.stem
    s = get_settings()
    require_proxmox(s)
    command = " ".join(sys.argv)
    op_id = create_operation("template_import", command, current_username(), tpl_name)
    spawn_background(op_id, "template_import", tpl_name, str(source))
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


@template_app.command("rename", hidden=not _caller_is_admin)
def template_rename(
    old_name: str = typer.Argument(..., help="Current template name."),
    new_name: str = typer.Argument(..., help="New template name."),
):
    """Rename a Proxmox template."""
    if not is_admin():
        typer.echo("error: lab template rename requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)
    mgr = TemplateManager(ProxmoxClient(s), s)
    mgr.rename(old_name, new_name)
    typer.echo(f"  renamed: {old_name} → {new_name}")



@template_app.command("delete", hidden=not _caller_is_admin)
def template_delete(name: str = typer.Argument(..., help="Template name (e.g. generic-x64-debian12).")):
    """Delete a Proxmox template VM."""
    if not is_admin():
        typer.echo("error: lab template delete requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)
    mgr = TemplateManager(ProxmoxClient(s), s)
    try:
        mgr.delete(name)
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  deleted: {name}")




# ── template ct ───────────────────────────────────────────────────────────────

@ct_app.command("list")
def ct_list():
    """List available LXC container templates from the Proxmox repository (admin only)."""
    if not is_admin():
        typer.echo("error: lab template ct list requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)
    px = ProxmoxClient(s)
    nodes = [n for n in px.get_nodes() if n.status == "online"]
    if not nodes:
        typer.echo("error: no online nodes found", err=True)
        raise typer.Exit(1)
    templates = px.list_ct_templates(nodes[0].name)
    if not templates:
        typer.echo("no CT templates available")
        return
    for t in templates:
        typer.echo(f"  {t}")


@ct_app.command("fetch")
def ct_fetch(
    name: str = typer.Argument(..., help="CT template name without extension (from 'lab template ct list')."),
):
    """Download a CT template to shared NFS storage (nfs-templates) (background)."""
    if not is_admin():
        typer.echo("error: lab template ct fetch requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)
    command = " ".join(sys.argv)
    op_id = create_operation("ct_template_fetch", command, current_username(), name)
    spawn_background(op_id, "ct_template_fetch", name)
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")



@ct_app.command("delete")
def ct_delete(
    name: str = typer.Argument(..., help="CT template name without extension (from 'lab template ct downloaded')."),
):
    """Delete a downloaded CT template from shared NFS storage."""
    if not is_admin():
        typer.echo("error: lab template ct delete requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    cache = Path(s.templates_dir) / "template" / "cache"
    matches = list(cache.glob(f"{name}.tar.*"))
    if not matches:
        typer.echo(f"error: template not found in {cache}", err=True)
        raise typer.Exit(1)
    target = matches[0]
    confirmed = typer.confirm(f"Delete {target.name}?", default=False)
    if not confirmed:
        typer.echo("aborted")
        raise typer.Exit(0)
    target.unlink()
    typer.echo(f"  deleted: {target.name}")


@ct_app.command("downloaded")
def ct_downloaded():
    """List CT templates already downloaded to shared NFS storage (admin only)."""
    if not is_admin():
        typer.echo("error: lab template ct downloaded requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)
    px = ProxmoxClient(s)
    nodes = [n for n in px.get_nodes() if n.status == "online"]
    if not nodes:
        typer.echo("error: no online nodes found", err=True)
        raise typer.Exit(1)
    templates = px.list_downloaded_ct_templates(nodes[0].name)
    if not templates:
        typer.echo("no CT templates downloaded yet")
        return
    for t in templates:
        typer.echo(f"  {t}")


@template_app.command("build", hidden=not _caller_is_admin)
def template_build(
    build_name: str = typer.Argument(..., help="Build name (e.g. nethsecurity, windows)."),
    version: str = typer.Argument(default="", help="Version (nethsecurity, e.g. 8.7.2) or Windows variant (11 | 2025)."),
    url: str = typer.Option("", "--url", help="Custom download URL (nethsecurity only)."),
    skip_update: bool = typer.Option(False, "--skip-update", help="Windows only: skip Windows Update during the build (default: updates run)."),
    skip_optimize: bool = typer.Option(False, "--skip-optimize", help="Windows only: skip the SDelete free-space zero-fill (default: it runs)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Windows only: print the detected node/storage/bridge/VLAN + patched config and exit, building nothing."),
):
    """Build a Proxmox template via Packer (background).

    nethsecurity is built via libvirt and imported; windows is built directly on a
    Proxmox node (--skip-update / --skip-optimize / --dry-run apply to windows only).
    """
    if not is_admin():
        typer.echo("error: lab template build requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)

    # --dry-run runs synchronously so the preview prints right here (no background op).
    if dry_run:
        from lab.build import BuildManager
        try:
            BuildManager(ProxmoxClient(s), s).build(
                build_name, version, log_fn=typer.echo,
                skip_update=skip_update, skip_optimize=skip_optimize, dry_run=True,
            )
        except (RuntimeError, ValueError, FileNotFoundError) as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1)
        return

    command = " ".join(sys.argv)
    target = f"{build_name}-{version}" if version else build_name
    op_id = create_operation("template_build", command, current_username(), target)
    spawn_background(
        op_id, "template_build", build_name, version, url,
        "1" if skip_update else "0", "1" if skip_optimize else "0",
    )
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


# ── template source ───────────────────────────────────────────────────────────

@source_app.command("add")
def source_add(
    build_name: str = typer.Argument(..., help="Build name (e.g. nethsecurity)."),
    file: str = typer.Argument(..., help="Path to source file (qcow2, img, vmdk, iso)."),
):
    """Stage a vendor source file for template building (background)."""
    if not is_admin():
        typer.echo("error: lab template source add requires admin", err=True)
        raise typer.Exit(1)
    source = Path(file).resolve()
    if not source.exists():
        typer.echo(f"error: file not found: {file}", err=True)
        raise typer.Exit(1)
    s = get_settings()
    command = " ".join(sys.argv)
    op_id = create_operation("template_source_add", command, current_username(), build_name)
    spawn_background(op_id, "template_source_add", build_name, str(source))
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


@source_app.command("list")
def source_list():
    """List staged vendor source files."""
    if not is_admin():
        typer.echo("error: lab template source list requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    from lab.build_sources import BuildSourceManager
    mgr = BuildSourceManager(s.build_sources_dir)
    files = mgr.list()
    if not files:
        typer.echo("no source files staged")
        return
    for f in files:
        size_mb = f["size"] / 1_048_576
        typer.echo(f"  {f['name']:<40}  {size_mb:.1f} MB")


@source_app.command("delete")
def source_delete(name: str = typer.Argument(..., help="Filename to delete (e.g. nethsecurity.img).")):
    """Delete a staged vendor source file."""
    if not is_admin():
        typer.echo("error: lab template source delete requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    from lab.build_sources import BuildSourceManager
    mgr = BuildSourceManager(s.build_sources_dir)
    mgr.delete(name)
    typer.echo(f"  deleted: {name}")


# ── deploy ────────────────────────────────────────────────────────────────────

def _resolve_scenario_path(scenario: str) -> Path:
    """Resolve a scenario argument to a Path.

    Accepts a full path (scenarios/vyos-lab/scenario.yml) or a bare name
    (vyos-lab) that maps to scenarios/<name>/scenario.yml.
    Raises FileNotFoundError if neither form exists.
    """
    p = Path(scenario)
    if p.exists():
        return p
    candidate = _PROJECT_ROOT / "scenarios" / scenario / "scenario.yml"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(scenario)


def _check_deploy_permission(user_flag: str) -> str:
    """Return effective username for deploy commands, raising ValueError on permission violations.

    Admin: --user <username> required; cannot target themselves.
    Regular user: --user unavailable; always deploys as themselves.
    """
    caller = current_username()
    if is_admin():
        if not user_flag:
            raise ValueError("admin must specify --user <username>")
        if user_flag == caller:
            raise ValueError("admin cannot deploy under themselves — specify a target user")
        return user_flag
    else:
        if user_flag:
            raise ValueError("--user is only available to admin")
        return caller


def _resolve_deploy_user(user_flag: str) -> str:
    """CLI wrapper: resolve effective username, printing error and exiting on violations."""
    try:
        return _check_deploy_permission(user_flag)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1)


@deploy_app.command("start", hidden=not _caller_is_admin)
def deploy_start(
    scenario: str = typer.Argument(..., help="Path to scenario YAML file."),
    user: str = typer.Option("", "--user", help="Target username (admin only)."),
    skip_ansible: bool = typer.Option(False, "--skip-ansible", help="Create VMs and start them, but skip Ansible provisioning."),
    target: str = typer.Option("", "--target", help="Deploy only these VMs/groups (comma-separated, incremental)."),
    no_headroom: bool = typer.Option(False, "--no-headroom", help="Skip RAM headroom check (use when host is near capacity)."),
):
    """Deploy a scenario (or add a single VM/group with --target) (admin only)."""
    if not is_admin():
        typer.echo("error: lab deploy start requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    from lab.scenario import parse_scenario

    s = get_settings()
    require_proxmox(s)
    effective_user = _resolve_deploy_user(user)

    # Pre-flight: verify target user exists
    from lab.deploy import _resolve_target, get_deployment_status, user_exists
    if not user_exists(effective_user):
        typer.echo(f"error: user '{effective_user}' not found — run 'lab user create {effective_user}' first", err=True)
        raise typer.Exit(1)

    # Pre-flight: parse scenario
    try:
        scenario_path = _resolve_scenario_path(scenario)
    except FileNotFoundError:
        typer.echo(f"error: scenario not found: {scenario}", err=True)
        raise typer.Exit(1)

    spec = parse_scenario(scenario_path)
    proxmox = ProxmoxClient(s)
    tmgr = TemplateManager(proxmox, s)

    label = scenario_path.parent.name or scenario_path.stem

    if target:
        # Validate target name and check only its templates
        try:
            target_specs = _resolve_target(spec, target)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1)

        missing = [
            vm.template for vm in target_specs
            if vm.type != "container" and tmgr.get_vmid(vm.template) is None
        ]

        # Deployment state check for target mode
        existing_status = get_deployment_status(effective_user, label)
        if existing_status == "deploying":
            typer.echo(f"error: deployment '{label}' is currently deploying — wait for it to finish", err=True)
            raise typer.Exit(1)
        # active, stopped, or failed → OK for --target (incremental add)
        # failed is allowed: previous --target may have failed before creating any VM
    else:
        # Full deploy: check all templates and block on existing active deployment
        missing = [
            vm.template for vm in spec.vms
            if vm.type != "container" and tmgr.get_vmid(vm.template) is None
        ]

        existing_status = get_deployment_status(effective_user, label)
        if existing_status in ("deploying", "active", "stopped"):
            typer.echo(
                f"error: deployment '{label}' is already {existing_status} — "
                f"use --target to add VMs, or destroy it first",
                err=True,
            )
            raise typer.Exit(1)
        if existing_status == "failed":
            typer.echo(f"note: previous deploy of '{label}' failed — will clean up automatically")

    if missing:
        seen = dict.fromkeys(missing)
        typer.echo("error: missing templates — fetch them first:", err=True)
        for tpl in seen:
            typer.echo(f"  lab template fetch {tpl}", err=True)
        raise typer.Exit(1)

    command = " ".join(sys.argv)
    op_id = create_operation("deploy_start", command, current_username(), label)
    spawn_background(op_id, "deploy_start", str(scenario_path), effective_user, "1" if skip_ansible else "0", target or "", "1" if no_headroom else "0")
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


@deploy_app.command("status")
def deploy_status(
    user: str = typer.Option("", "--user", help="Filter by username (admin only)."),
):
    """List all active deployments. Admin sees all users; others see only their own."""
    if user and not is_admin():
        typer.echo("error: --user is only available to admin", err=True)
        raise typer.Exit(1)

    from lab.db import get_conn as _get_conn

    caller = current_username()

    with _get_conn() as conn:
        with conn.cursor() as cur:
            if is_admin() and not user:
                cur.execute(
                    """
                    SELECT d.name, d.status, d.created_at, u.username,
                           COUNT(v.id) AS vm_count
                    FROM deployments d
                    JOIN users u ON u.id = d.user_id
                    LEFT JOIN vms v ON v.deployment_id = d.id
                    WHERE d.status != 'destroyed'
                    GROUP BY d.id, u.username
                    ORDER BY u.username, d.name
                    """,
                )
            else:
                filter_user = user if (is_admin() and user) else caller
                cur.execute(
                    """
                    SELECT d.name, d.status, d.created_at, u.username,
                           COUNT(v.id) AS vm_count
                    FROM deployments d
                    JOIN users u ON u.id = d.user_id
                    LEFT JOIN vms v ON v.deployment_id = d.id
                    WHERE d.status != 'destroyed' AND u.username = %s
                    GROUP BY d.id, u.username
                    ORDER BY d.name
                    """,
                    (filter_user,),
                )
            rows = cur.fetchall()

    if not rows:
        typer.echo("no active deployments")
        return

    typer.echo(f"  {'USER':<16}  {'NAME':<20}  {'STATUS':<14}  VMs  CREATED")
    for row in rows:
        created = row["created_at"].strftime("%Y-%m-%d") if row["created_at"] else "-"
        typer.echo(
            f"  {row['username']:<16}  {row['name']:<20}  {row['status']:<14}"
            f"  {row['vm_count']:>3}  {created}"
        )


@deploy_app.command("show")
def deploy_show(
    deployment: str = typer.Argument(..., help="Deployment name."),
    user: str = typer.Option("", "--user", help="Target username (admin only)."),
):
    """Show VMs and details for a deployment."""
    if user and not is_admin():
        typer.echo("error: --user is only available to admin", err=True)
        raise typer.Exit(1)

    from lab.db import get_conn as _get_conn

    effective_user = user if user else current_username()

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT d.id, d.status, d.created_at, u.username
                FROM deployments d
                JOIN users u ON u.id = d.user_id
                WHERE d.name = %s AND u.username = %s
                ORDER BY d.created_at DESC LIMIT 1
                """,
                (deployment, effective_user),
            )
            dep = cur.fetchone()

    if not dep:
        typer.echo(f"error: deployment '{deployment}' not found for user '{effective_user}'", err=True)
        raise typer.Exit(1)

    dep_id = dep["id"]
    typer.echo(f"\n  deployment: {deployment}   status: {dep['status']}   user: {dep['username']}\n")

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, vmid, node, management_ip, mac_address, status, ansible_status FROM vms WHERE deployment_id=%s ORDER BY vmid",
                (dep_id,),
            )
            vms = cur.fetchall()
            cur.execute(
                """
                SELECT n.vmid, n.slot, n.iface_name, n.network, n.vnet, n.mac, n.ip
                FROM vm_nics n
                JOIN vms v ON v.vmid = n.vmid
                WHERE v.deployment_id = %s
                ORDER BY n.vmid, n.slot
                """,
                (dep_id,),
            )
            all_nics = cur.fetchall()

    nics_by_vmid: dict[int, list] = {}
    for nic in all_nics:
        nics_by_vmid.setdefault(nic["vmid"], []).append(nic)

    if not vms:
        typer.echo("  (no VMs)")
    else:
        total = len(vms)
        for i, vm in enumerate(vms):
            typer.echo(
                f"  {vm['name']}   VMID={vm['vmid']}  node={vm['node'] or '?'}"
                f"  status={vm['status']}  ansible={vm['ansible_status']}"
            )
            nics = nics_by_vmid.get(vm["vmid"] or 0, [])
            if nics:
                typer.echo(f"  {'IFACE':<10} {'SLOT':<6} {'NETWORK':<18} {'VNET/BRIDGE':<16} {'MAC':<18} IP")
                for nic in nics:
                    ip_str = nic["ip"] or "—"
                    typer.echo(
                        f"  {nic['iface_name']:<10} {nic['slot']:<6} {nic['network']:<18} {nic['vnet']:<16} {nic['mac']:<18} {ip_str}"
                    )
            typer.echo("")
            shown = i + 1
            if shown < total and shown % _PAGE_SIZE == 0:
                if not _pager_prompt(shown, total):
                    typer.echo(f"  (stopped at {shown}/{total})\n")
                    return
    typer.echo("")


@deploy_app.command("stop", hidden=not _caller_is_admin)
def deploy_stop(
    deployment: str = typer.Argument(..., help="Deployment name."),
    user: str = typer.Option("", "--user", help="Target username (admin only)."),
):
    """Stop all VMs in a deployment (does not delete) (admin only)."""
    if not is_admin():
        typer.echo("error: lab deploy stop requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    s = get_settings()
    require_proxmox(s)
    effective_user = _resolve_deploy_user(user)

    command = " ".join(sys.argv)
    op_id = create_operation("deploy_stop", command, current_username(), deployment)
    spawn_background(op_id, "deploy_stop", deployment, effective_user)
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


@deploy_app.command("resume", hidden=not _caller_is_admin)
def deploy_resume(
    deployment: str = typer.Argument(..., help="Deployment name."),
    user: str = typer.Option("", "--user", help="Target username (admin only)."),
):
    """Start all VMs in a stopped deployment and mark it active (admin only)."""
    if not is_admin():
        typer.echo("error: lab deploy resume requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    s = get_settings()
    require_proxmox(s)
    effective_user = _resolve_deploy_user(user)

    command = " ".join(sys.argv)
    op_id = create_operation("deploy_resume", command, current_username(), deployment)
    spawn_background(op_id, "deploy_resume", deployment, effective_user)
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


@deploy_app.command("destroy", hidden=not _caller_is_admin)
def deploy_destroy(
    deployment: str = typer.Argument(..., help="Deployment name."),
    user: str = typer.Option("", "--user", help="Target username (admin only)."),
    target: str = typer.Option("", "--target", help="Destroy only these VMs/groups (comma-separated, cascades to dependents)."),
    no_cascade: bool = typer.Option(False, "--no-cascade", help="With --target: destroy only the named VMs, do not cascade to dependents."),
):
    """Destroy a deployment (or a targeted VM/group with --target) (admin only)."""
    if not is_admin():
        typer.echo("error: lab deploy destroy requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    s = get_settings()
    require_proxmox(s)
    effective_user = _resolve_deploy_user(user)

    if target:
        from lab.deploy import get_target_destroy_preview
        try:
            preview = get_target_destroy_preview(deployment, effective_user, target, cascade=not no_cascade)
        except RuntimeError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1)

        typer.echo(f"\n  The following will be destroyed (target: {target}, user: {effective_user}):\n")
        for vm_name, label in preview:
            marker = "  ← target" if label == "target" else ""
            typer.echo(f"    {vm_name}{marker}")
        typer.echo("")
        confirmed = typer.confirm("Destroy these VMs?", default=False)
    else:
        typer.echo(f"\n  Deployment to destroy: {deployment} (user: {effective_user})")
        typer.echo("  All VMs and VNets will be deleted.\n")
        confirmed = typer.confirm("Destroy this deployment?", default=False)

    if not confirmed:
        typer.echo("aborted")
        raise typer.Exit(0)

    command = " ".join(sys.argv)
    op_id = create_operation("deploy_destroy", command, current_username(), deployment)
    spawn_background(op_id, "deploy_destroy", deployment, effective_user, target or "", "1" if no_cascade else "0")
    typer.echo(f"operation {op_id} started — get logs with command below:\n  $ lab ops logs {op_id} --follow")


# ── user ──────────────────────────────────────────────────────────────────────

@user_app.command("create")
def user_create(
    username: str = typer.Argument(..., help="Username for the new user."),
    password: str = typer.Option("", "--password", help="Password (default: auto-generated)."),
    ssh_key: str = typer.Option("", "--ssh-key", help="SSH public key to add to authorized_keys."),
):
    """Create a lab user: DB record, linux account, SDN VNet, management NIC."""
    if not is_admin():
        typer.echo("error: lab user create requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)

    from lab.users import UserManager, generate_password
    mgr = UserManager(ProxmoxClient(s), s)

    if mgr.get_user(username):
        typer.echo(f"error: user '{username}' already exists", err=True)
        raise typer.Exit(1)

    pw = password or generate_password()
    if not password:
        typer.echo(f"  generated password: {pw}")
        typer.echo("  (save it now — it will not be shown again)")

    try:
        mgr.create(username, pw, ssh_key=ssh_key, log_fn=typer.echo)
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)


@user_app.command("list")
def user_list():
    """List all platform users."""
    if not is_admin():
        typer.echo("error: lab user list requires admin", err=True)
        raise typer.Exit(1)
    s = get_settings()
    from lab.users import UserManager
    mgr = UserManager(None, s)
    users = mgr.list_users()
    if not users:
        typer.echo("no users")
        return
    typer.echo(f"  {'ID':<4}  {'USERNAME':<20}  {'ROLE':<8}  {'NIC':<8}  CREATED")
    for u in users:
        created = u["created_at"].strftime("%Y-%m-%d") if u["created_at"] else "-"
        typer.echo(
            f"  {u['user_id']:<4}  {u['username']:<20}  {u['role']:<8}  "
            f"{(u['mgmt_nic'] or '-'):<8}  {created}"
        )


@user_app.command("delete")
def user_delete(username: str = typer.Argument(..., help="Username to delete.")):
    """Delete a platform user and all associated resources."""
    if not is_admin():
        typer.echo("error: lab user delete requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)
    s = get_settings()
    require_proxmox(s)

    from lab.users import UserManager
    mgr = UserManager(ProxmoxClient(s), s)

    # preview what will be deleted
    user = mgr.get_user(username)
    if not user:
        typer.echo(f"error: user '{username}' not found", err=True)
        raise typer.Exit(1)

    vms = mgr.get_user_vms(username)
    running = [v for v in vms if v["status"] == "running"]

    typer.echo(f"\n  User to delete: {username} (user_id={user['user_id']}, role={user['role']})")
    if vms:
        typer.echo(f"  VMs: {len(vms)} total, {len(running)} running")
        for v in vms:
            marker = " [RUNNING]" if v["status"] == "running" else ""
            typer.echo(f"    VMID {v['vmid']}  {v['vm_name']}  ({v['deployment_name']}){marker}")
    else:
        typer.echo("  VMs: none")

    vnet = f"mgmt{user['user_id']}"
    typer.echo(f"  SDN VNet: {vnet}")
    typer.echo(f"  NIC on mgmt VM: {user['mgmt_nic'] or 'unknown'}")
    typer.echo(f"  Network config: /etc/systemd/network/10-mgmt-{user['user_id']}.network")
    typer.echo(f"  Linux account: {username}")

    if running:
        typer.echo(f"\n  WARNING: {len(running)} VM(s) are currently running and will be force-stopped.")

    typer.echo("")
    confirmed = typer.confirm("Delete this user and all resources listed above?", default=False)
    if not confirmed:
        typer.echo("aborted")
        raise typer.Exit(0)

    mgr.delete(username, log_fn=typer.echo)


@user_app.command("reset-password")
def user_reset_password(
    username: str = typer.Argument(..., help="Username to reset password for."),
    password: str = typer.Option("", "--password", help="New password (default: auto-generated)."),
):
    """Reset a user's password."""
    if not is_admin():
        typer.echo("error: lab user reset-password requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)
    s = get_settings()

    from lab.users import UserManager, generate_password
    pw = password or generate_password()
    if not password:
        typer.echo(f"  generated password: {pw}")
        typer.echo("  (save it now — it will not be shown again)")

    mgr = UserManager(None, s)
    mgr.reset_password(username, pw, log_fn=typer.echo)


# ── ops ───────────────────────────────────────────────────────────────────────

_STATUS_COLORS = {
    "completed":  typer.colors.GREEN,
    "failed":     typer.colors.RED,
    "incomplete": typer.colors.YELLOW,
    "running":    typer.colors.YELLOW,
    "started":    typer.colors.WHITE,
}

_LEVEL_COLORS = {
    "error": typer.colors.RED,
    "warn":  typer.colors.YELLOW,
    "info":  typer.colors.WHITE,
}


@ops_app.command("list")
def ops_list(
    limit: int  = typer.Option(20,   help="Number of operations to show (0 = no limit)."),
    all:   bool = typer.Option(False, "--all", help="Show all operations (no limit)."),
    status: str = typer.Option("",   help="Filter by status: started|running|completed|failed|incomplete."),
    user:   str = typer.Option("",   "--user", help="Filter by username (admin only)."),
):
    """List background operations (admin only)."""
    if not is_admin():
        typer.echo("error: lab ops list requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    username = current_username()

    effective_limit = None if all else (None if limit == 0 else limit)

    rows = list_operations(
        username=username,
        user_filter=user or None,
        status_filter=status or None,
        limit=effective_limit,
    )

    if not rows:
        typer.echo("no operations found")
        return

    for row in rows:
        status_color = _STATUS_COLORS.get(row["status"], typer.colors.WHITE)
        duration = format_duration(row["started_at"], row["completed_at"])
        status_str = typer.style(f"{row['status']:<10}", fg=status_color)
        typer.echo(
            f"  {row['id']:>5}  {status_str}  {row['username']:<12}  "
            f"{duration:>6}  {row['command']}"
        )


def _print_log_entry(entry: dict) -> None:
    color = _LEVEL_COLORS.get(entry["level"], typer.colors.WHITE)
    ts = entry["ts"].strftime("%H:%M:%S")
    prefix = typer.style(f"[{ts}] [{entry['level'].upper():<5}]", fg=color)
    typer.echo(f"  {prefix}  {entry['message']}")


@ops_app.command("logs")
def ops_logs(
    op_id:  int  = typer.Argument(..., help="Operation ID."),
    errors: bool = typer.Option(False, "--errors", help="Show only error lines."),
    tail:   int  = typer.Option(0,    "--tail",   help="Show last N lines (0 = all)."),
    follow: bool = typer.Option(False, "--follow", "-f", help="Poll for new lines until operation completes."),
):
    """Show log output for an operation (admin only)."""
    if not is_admin():
        typer.echo("error: lab ops logs requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    level = "error" if errors else None

    if follow:
        last_id = 0
        try:
            while True:
                new_logs = get_logs(op_id, level=level, after_id=last_id)
                for entry in new_logs:
                    _print_log_entry(entry)
                    last_id = entry["id"]
                op = get_operation(op_id)
                if op and op["status"] in ("completed", "failed", "cancelled", "incomplete"):
                    break
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        return

    logs = get_logs(op_id, level=level, tail=tail if tail > 0 else None)

    if not logs:
        typer.echo("no log entries found")
        return

    for entry in logs:
        _print_log_entry(entry)


@ops_app.command("cancel")
def ops_cancel(
    op_id: int = typer.Argument(..., help="Operation ID to cancel."),
):
    """Cancel a running operation (admin only)."""
    if not is_admin():
        typer.echo("error: lab ops cancel requires admin (root or sudo group)", err=True)
        raise typer.Exit(1)

    username = current_username()
    try:
        op = get_operation(op_id)
        cancel_operation(op_id, username=username)
        typer.echo(f"operation {op_id} cancelled")

        if op and op["type"] in ("template_fetch", "template_import"):
            other_running = list_operations(username=username, status_filter="running")
            other_template_ops = [
                o for o in other_running
                if o["type"] in ("template_fetch", "template_import") and o["id"] != op_id
            ]
            if other_template_ops:
                typer.echo("note: other template operations are running — skipping NFS cleanup")
            else:
                settings = Settings()
                client = ProxmoxClient(settings)
                removed = TemplateManager(client, settings).cleanup_orphaned_slots()
                if removed:
                    vmids = ", ".join(str(v) for v in removed)
                    typer.echo(f"cleaned up orphaned NFS slot(s): {vmids}")
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)


# ── gc ────────────────────────────────────────────────────────────────────────

@app.command(hidden=not _caller_is_admin)
def gc(
    dry_run: bool = typer.Option(False, "--dry-run", help="Report orphans without making changes."),
):
    """Garbage-collect orphaned platform resources (admin only).

    Cleans up resources left by crashes or interrupted operations:
    stuck operations, half-imported templates, orphan VMs/VNets, stale DHCP entries,
    and unused management VM NICs.
    """
    from lab.gc import run_gc

    if not is_admin():
        typer.echo("error: lab gc requires admin privileges", err=True)
        raise typer.Exit(1)

    s = get_settings()
    require_proxmox(s)
    proxmox = ProxmoxClient(s)

    if dry_run:
        typer.echo("running in dry-run mode — no changes will be made\n")

    results = run_gc(proxmox, s.mgmt_vmid, dry_run=dry_run, log_fn=typer.echo)

    total = sum(results.values())
    typer.echo("")
    typer.echo("── summary ──────────────────────────────────────")
    for category, count in results.items():
        if count > 0:
            label = "[dry-run] would fix" if dry_run else "fixed"
            typer.echo(f"  {category:<16}  {count:>3}  {label}")
        else:
            typer.echo(f"  {category:<16}    0  clean")
    typer.echo(f"\n  total: {total}")
    if total > 0 and not dry_run:
        typer.echo("gc complete")
    elif total > 0 and dry_run:
        typer.echo("re-run without --dry-run to apply changes")
    else:
        typer.echo("nothing to clean up")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        typer.echo("\nAborted.", err=True)
        raise SystemExit(130)


