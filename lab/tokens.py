from __future__ import annotations

import datetime
import secrets

from lab.db import get_conn

_TTL_HOURS = 24


def create_token(vmid: int, node: str) -> str:
    token = secrets.token_hex(16)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=_TTL_HOURS)
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Clean up expired tokens on every write to keep the table small.
            cur.execute("DELETE FROM console_tokens WHERE expires_at < NOW()")
            cur.execute(
                "INSERT INTO console_tokens (token, vmid, node, expires_at) VALUES (%s, %s, %s, %s)",
                (token, vmid, node, expires_at),
            )
    return token


def resolve_token(token: str) -> dict | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT vmid, node FROM console_tokens WHERE token = %s AND expires_at > NOW()",
                (token,),
            )
            return cur.fetchone()
