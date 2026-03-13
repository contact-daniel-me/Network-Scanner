"""
database.py – SQLite persistence for traffic logs, blocked IPs, and alerts.
"""

import sqlite3
import contextlib
import os


def _db_path(app):
    return app.config["DATABASE_PATH"]


# In-memory databases need a persistent connection so that tables created by
# init_db() are visible to subsequent queries within the same test run.
_in_memory_conns: dict = {}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT,
    protocol    TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    packet_size INTEGER,
    flags       TEXT,
    action      TEXT    NOT NULL DEFAULT 'ALLOWED'
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT    NOT NULL UNIQUE,
    reason      TEXT,
    blocked_at  TEXT    NOT NULL,
    unblock_at  TEXT,
    is_active   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    alert_type  TEXT    NOT NULL,
    description TEXT,
    action_taken TEXT
);
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def get_conn(app):
    """Yield a sqlite3 connection that auto-commits and closes."""
    path = _db_path(app)

    if path == ":memory:":
        # Keep a single persistent connection per app instance so that tables
        # created by init_db() survive across requests within the same test.
        app_id = id(app)
        if app_id not in _in_memory_conns:
            c = sqlite3.connect(":memory:", check_same_thread=False)
            c.row_factory = sqlite3.Row
            _in_memory_conns[app_id] = c
        conn = _in_memory_conns[app_id]
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    else:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db(app):
    """Create tables if they do not exist."""
    with get_conn(app) as conn:
        conn.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# Traffic logs
# ---------------------------------------------------------------------------

def insert_traffic_log(app, log: dict):
    sql = """
        INSERT INTO traffic_logs
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
             packet_size, flags, action)
        VALUES
            (:timestamp, :src_ip, :dst_ip, :protocol, :src_port, :dst_port,
             :packet_size, :flags, :action)
    """
    with get_conn(app) as conn:
        conn.execute(sql, log)


def get_recent_traffic(app, limit: int = 100):
    sql = """
        SELECT * FROM traffic_logs
        ORDER BY id DESC
        LIMIT ?
    """
    with get_conn(app) as conn:
        rows = conn.execute(sql, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_traffic_stats(app):
    """Return aggregate counts for the dashboard."""
    sql = """
        SELECT
            COUNT(*)                                        AS total,
            SUM(CASE WHEN action = 'BLOCKED'  THEN 1 ELSE 0 END) AS blocked,
            SUM(CASE WHEN action = 'FLAGGED'  THEN 1 ELSE 0 END) AS flagged,
            SUM(CASE WHEN action = 'ALLOWED'  THEN 1 ELSE 0 END) AS allowed
        FROM traffic_logs
    """
    with get_conn(app) as conn:
        row = conn.execute(sql).fetchone()
    return dict(row) if row else {"total": 0, "blocked": 0, "flagged": 0, "allowed": 0}


def get_traffic_over_time(app, minutes: int = 5):
    """Return per-minute packet counts for the last *minutes* minutes."""
    sql = """
        SELECT
            strftime('%Y-%m-%dT%H:%M', timestamp) AS minute,
            COUNT(*) AS count
        FROM traffic_logs
        WHERE timestamp >= datetime('now', ?)
        GROUP BY minute
        ORDER BY minute
    """
    with get_conn(app) as conn:
        rows = conn.execute(sql, (f"-{minutes} minutes",)).fetchall()
    return [dict(r) for r in rows]


def get_protocol_distribution(app):
    sql = """
        SELECT protocol, COUNT(*) AS count
        FROM traffic_logs
        GROUP BY protocol
    """
    with get_conn(app) as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Blocked IPs
# ---------------------------------------------------------------------------

def block_ip(app, ip: str, reason: str, blocked_at: str, unblock_at=None):
    sql = """
        INSERT INTO blocked_ips (ip_address, reason, blocked_at, unblock_at, is_active)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(ip_address) DO UPDATE SET
            reason     = excluded.reason,
            blocked_at = excluded.blocked_at,
            unblock_at = excluded.unblock_at,
            is_active  = 1
    """
    with get_conn(app) as conn:
        conn.execute(sql, (ip, reason, blocked_at, unblock_at))


def unblock_ip(app, ip: str):
    sql = "UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ?"
    with get_conn(app) as conn:
        conn.execute(sql, (ip,))


def is_ip_blocked(app, ip: str) -> bool:
    sql = """
        SELECT 1 FROM blocked_ips
        WHERE ip_address = ?
          AND is_active = 1
          AND (unblock_at IS NULL OR unblock_at > datetime('now'))
    """
    with get_conn(app) as conn:
        row = conn.execute(sql, (ip,)).fetchone()
    return row is not None


def get_blocked_ips(app):
    sql = """
        SELECT * FROM blocked_ips
        WHERE is_active = 1
          AND (unblock_at IS NULL OR unblock_at > datetime('now'))
        ORDER BY blocked_at DESC
    """
    with get_conn(app) as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def expire_blocks(app):
    """Mark expired blocks as inactive."""
    sql = """
        UPDATE blocked_ips
        SET is_active = 0
        WHERE is_active = 1 AND unblock_at IS NOT NULL AND unblock_at <= datetime('now')
    """
    with get_conn(app) as conn:
        conn.execute(sql)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def insert_alert(app, alert: dict):
    sql = """
        INSERT INTO alerts (timestamp, src_ip, alert_type, description, action_taken)
        VALUES (:timestamp, :src_ip, :alert_type, :description, :action_taken)
    """
    with get_conn(app) as conn:
        conn.execute(sql, alert)


def get_recent_alerts(app, limit: int = 50):
    sql = "SELECT * FROM alerts ORDER BY id DESC LIMIT ?"
    with get_conn(app) as conn:
        rows = conn.execute(sql, (limit,)).fetchall()
    return [dict(r) for r in rows]
