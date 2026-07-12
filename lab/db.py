from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

import psycopg2
import psycopg2.extras

from lab.config import get_settings


@contextmanager
def get_conn() -> Generator:
    conn = psycopg2.connect(
        get_settings().db_url,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
