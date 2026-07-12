from __future__ import annotations

import grp
import os
import pwd
import signal
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

from lab.db import get_conn


# ── identity ──────────────────────────────────────────────────────────────────

def current_username() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def _is_admin(uid: int, username: str) -> bool:
    """Pure: True if uid is root or username is in the sudo group."""
    if uid == 0:
        return True
    try:
        return username in grp.getgrnam("sudo").gr_mem
    except KeyError:
        return False


def is_admin() -> bool:
    return _is_admin(os.getuid(), current_username())


# ── operations ────────────────────────────────────────────────────────────────

def create_operation(op_type: str, command: str, username: str, target: str) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO operations (type, command, username, target, status)
                VALUES (%s, %s, %s, %s, 'started')
                RETURNING id
                """,
                (op_type, command, username, target),
            )
            return cur.fetchone()["id"]


def set_running(op_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operations SET status='running' WHERE id=%s",
                (op_id,),
            )


def complete_operation(op_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operations SET status='completed', completed_at=NOW() WHERE id=%s",
                (op_id,),
            )


def fail_operation(op_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operations SET status='failed', completed_at=NOW() WHERE id=%s",
                (op_id,),
            )


def incomplete_operation(op_id: int) -> None:
    """Mark an operation as not completed due to an expected, handled condition
    (e.g. insufficient capacity) rather than an unexpected failure worth
    investigating as a bug. Distinct from fail_operation so `lab ops list`
    doesn't flag a resource constraint the same way it flags a real crash.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operations SET status='incomplete', completed_at=NOW() WHERE id=%s",
                (op_id,),
            )



def append_log(op_id: int, message: str, level: str = "info") -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO operation_logs (operation_id, level, message) VALUES (%s, %s, %s)",
                (op_id, level, message.strip()),
            )


# ── queries ───────────────────────────────────────────────────────────────────

def build_ops_query(
    *,
    admin: bool,
    username: str,
    user_filter: str | None,
    status_filter: str | None,
    limit: int | None,
) -> tuple[str, list[Any]]:
    """Return (sql, params) for the operations list query. Pure — no DB access."""
    conditions: list[str] = []
    params: list[Any] = []

    if not admin:
        conditions.append("username = %s")
        params.append(username)
    elif user_filter:
        conditions.append("username = %s")
        params.append(user_filter)

    if status_filter:
        conditions.append("status = %s")
        params.append(status_filter)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    limit_clause = f"LIMIT {limit}" if limit else ""
    sql = f"SELECT * FROM operations {where} ORDER BY started_at DESC {limit_clause}"
    return sql.strip(), params


def build_logs_query(
    op_id: int,
    *,
    level: str | None,
    tail: int | None,
    after_id: int | None = None,
) -> tuple[str, list[Any]]:
    """Return (sql, params) for the operation_logs query. Pure — no DB access."""
    conditions = ["operation_id = %s"]
    params: list[Any] = [op_id]

    if level:
        conditions.append("level = %s")
        params.append(level)

    if after_id is not None:
        conditions.append("id > %s")
        params.append(after_id)

    where = "WHERE " + " AND ".join(conditions)

    if tail:
        sql = (
            f"SELECT * FROM (SELECT * FROM operation_logs {where} "
            f"ORDER BY id DESC LIMIT {tail}) sub ORDER BY id ASC"
        )
    else:
        sql = f"SELECT * FROM operation_logs {where} ORDER BY id ASC"

    return sql, params


def list_operations(
    *,
    username: str,
    user_filter: str | None = None,
    status_filter: str | None = None,
    limit: int | None = 20,
) -> list[dict[str, Any]]:
    sql, params = build_ops_query(
        admin=is_admin(),
        username=username,
        user_filter=user_filter,
        status_filter=status_filter,
        limit=limit,
    )
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


def get_logs(
    op_id: int,
    *,
    level: str | None = None,
    tail: int | None = None,
    after_id: int | None = None,
) -> list[dict[str, Any]]:
    sql, params = build_logs_query(op_id, level=level, tail=tail, after_id=after_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


def get_operation(op_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM operations WHERE id = %s", (op_id,))
            row = cur.fetchone()
            return dict(row) if row else None


# ── background spawn ──────────────────────────────────────────────────────────

def spawn_background(op_id: int, task: str, *args: str) -> None:
    proc = subprocess.Popen(
        [sys.executable, "-m", "lab._bg", str(op_id), task, *args],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE operations SET pid=%s WHERE id=%s", (proc.pid, op_id))


def cancel_operation(op_id: int, *, username: str) -> None:
    """Send SIGTERM to the operation's process group and mark it cancelled.

    Raises RuntimeError if the operation is not found, not owned by the user,
    or is already finished.
    """
    op = get_operation(op_id)
    if op is None:
        raise RuntimeError(f"operation {op_id} not found")
    if not is_admin() and op["username"] != username:
        raise RuntimeError(f"operation {op_id} belongs to another user")
    if op["status"] not in ("started", "running"):
        raise RuntimeError(f"operation {op_id} is already {op['status']}")

    pid = op.get("pid")
    if not pid:
        # Fallback for ops started before PID tracking: scan /proc for the worker process.
        result = subprocess.run(
            ["pgrep", "-f", f"lab._bg {op_id} "],
            capture_output=True, text=True,
        )
        pids = [int(p) for p in result.stdout.split() if p.strip().isdigit()]
        pid = pids[0] if pids else None

    if pid:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass  # already dead

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operations SET status='cancelled', completed_at=NOW() WHERE id=%s",
                (op_id,),
            )


# ── formatting helpers ────────────────────────────────────────────────────────

def format_duration(started_at: datetime, completed_at: datetime | None) -> str:
    end = completed_at or datetime.now(timezone.utc)
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    secs = int((end - started_at).total_seconds())
    if secs < 60:
        return f"{secs}s"
    return f"{secs // 60}m{secs % 60:02d}s"
