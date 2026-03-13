"""
test_database.py – Unit tests for the database module.

Each test gets its own in-memory SQLite database so tests are isolated.
"""

import unittest
from datetime import datetime, timezone

from app import create_app
from app.database import (
    insert_traffic_log,
    get_recent_traffic,
    get_traffic_stats,
    get_protocol_distribution,
    block_ip,
    unblock_ip,
    is_ip_blocked,
    get_blocked_ips,
    expire_blocks,
    insert_alert,
    get_recent_alerts,
)


def _make_app():
    return create_app({
        "TESTING": True,
        "DATABASE_PATH": ":memory:",
    })


def _log(src_ip="1.2.3.4", action="ALLOWED", protocol="TCP", dst_port=80):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "protocol": protocol,
        "src_port": 12345,
        "dst_port": dst_port,
        "packet_size": 64,
        "flags": "S",
        "action": action,
    }


class TestTrafficLogs(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()

    def test_insert_and_retrieve(self):
        insert_traffic_log(self.app, _log())
        rows = get_recent_traffic(self.app, limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["src_ip"], "1.2.3.4")

    def test_limit_respected(self):
        for _ in range(10):
            insert_traffic_log(self.app, _log())
        rows = get_recent_traffic(self.app, limit=5)
        self.assertEqual(len(rows), 5)

    def test_stats_counts(self):
        insert_traffic_log(self.app, _log(action="ALLOWED"))
        insert_traffic_log(self.app, _log(action="BLOCKED"))
        insert_traffic_log(self.app, _log(action="FLAGGED"))
        stats = get_traffic_stats(self.app)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["allowed"], 1)
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["flagged"], 1)

    def test_protocol_distribution(self):
        insert_traffic_log(self.app, _log(protocol="TCP"))
        insert_traffic_log(self.app, _log(protocol="TCP"))
        insert_traffic_log(self.app, _log(protocol="UDP"))
        dist = {r["protocol"]: r["count"] for r in get_protocol_distribution(self.app)}
        self.assertEqual(dist["TCP"], 2)
        self.assertEqual(dist["UDP"], 1)


class TestBlockedIPs(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()
        self.ts = datetime.now(timezone.utc).isoformat()

    def test_block_and_query(self):
        block_ip(self.app, "5.5.5.5", "test block", self.ts)
        self.assertTrue(is_ip_blocked(self.app, "5.5.5.5"))

    def test_unblock(self):
        block_ip(self.app, "5.5.5.5", "test", self.ts)
        unblock_ip(self.app, "5.5.5.5")
        self.assertFalse(is_ip_blocked(self.app, "5.5.5.5"))

    def test_list_blocked(self):
        block_ip(self.app, "5.5.5.5", "r1", self.ts)
        block_ip(self.app, "6.6.6.6", "r2", self.ts)
        rows = get_blocked_ips(self.app)
        ips = {r["ip_address"] for r in rows}
        self.assertIn("5.5.5.5", ips)
        self.assertIn("6.6.6.6", ips)

    def test_reblock_updates_record(self):
        block_ip(self.app, "5.5.5.5", "first", self.ts)
        block_ip(self.app, "5.5.5.5", "second", self.ts)
        rows = get_blocked_ips(self.app)
        entry = next(r for r in rows if r["ip_address"] == "5.5.5.5")
        self.assertEqual(entry["reason"], "second")

    def test_expire_blocks(self):
        # unblock_at in the past → should become inactive after expire_blocks().
        past_ts = "2000-01-01T00:00:00+00:00"
        block_ip(self.app, "7.7.7.7", "expired", self.ts, unblock_at=past_ts)
        expire_blocks(self.app)
        self.assertFalse(is_ip_blocked(self.app, "7.7.7.7"))


class TestAlerts(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()

    def test_insert_and_retrieve(self):
        insert_alert(self.app, {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": "9.9.9.9",
            "alert_type": "PORT_SCAN",
            "description": "Scanned 15 ports",
            "action_taken": "BLOCKED",
        })
        alerts = get_recent_alerts(self.app)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["src_ip"], "9.9.9.9")
        self.assertEqual(alerts[0]["alert_type"], "PORT_SCAN")


if __name__ == "__main__":
    unittest.main()
