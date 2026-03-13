"""
test_routes.py – Integration tests for the REST API.
"""

import json
import unittest

from app import create_app
from app.database import insert_traffic_log, block_ip
from datetime import datetime, timezone


def _make_app():
    return create_app({
        "TESTING": True,
        "DATABASE_PATH": ":memory:",
        "AUTO_BLOCK": False,
    })


def _log(src_ip="1.2.3.4", action="ALLOWED", protocol="TCP"):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "protocol": protocol,
        "src_port": 12345,
        "dst_port": 80,
        "packet_size": 64,
        "flags": "S",
        "action": action,
    }


class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()
        self.client = self.app.test_client()

    def test_index_returns_html(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Network Scanner", res.data)


class TestTrafficAPI(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()
        self.client = self.app.test_client()
        for i in range(3):
            insert_traffic_log(self.app, _log(src_ip=f"1.2.3.{i + 1}"))

    def test_traffic_list(self):
        res = self.client.get("/api/traffic")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(len(data), 3)

    def test_traffic_limit(self):
        res = self.client.get("/api/traffic?limit=2")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(len(data), 2)


class TestStatsAPI(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()
        self.client = self.app.test_client()
        insert_traffic_log(self.app, _log(action="ALLOWED"))
        insert_traffic_log(self.app, _log(action="BLOCKED"))
        insert_traffic_log(self.app, _log(action="FLAGGED"))

    def test_stats(self):
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["allowed"], 1)
        self.assertEqual(data["blocked"], 1)
        self.assertEqual(data["flagged"], 1)

    def test_timeline(self):
        res = self.client.get("/api/stats/timeline")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(json.loads(res.data), list)

    def test_protocols(self):
        res = self.client.get("/api/stats/protocols")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(json.loads(res.data), list)


class TestBlockedIPsAPI(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()
        self.client = self.app.test_client()

    def test_empty_blocked_list(self):
        res = self.client.get("/api/blocked")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.data), [])

    def test_block_and_list(self):
        res = self.client.post(
            "/api/blocked",
            json={"ip": "5.5.5.5", "reason": "test"},
        )
        self.assertEqual(res.status_code, 201)
        data = json.loads(self.client.get("/api/blocked").data)
        ips = [r["ip_address"] for r in data]
        self.assertIn("5.5.5.5", ips)

    def test_block_invalid_ip(self):
        res = self.client.post("/api/blocked", json={"ip": "not-an-ip"})
        self.assertEqual(res.status_code, 400)

    def test_block_missing_ip(self):
        res = self.client.post("/api/blocked", json={})
        self.assertEqual(res.status_code, 400)

    def test_duplicate_block(self):
        self.client.post("/api/blocked", json={"ip": "5.5.5.5"})
        res = self.client.post("/api/blocked", json={"ip": "5.5.5.5"})
        self.assertEqual(res.status_code, 409)

    def test_unblock(self):
        self.client.post("/api/blocked", json={"ip": "5.5.5.5"})
        res = self.client.delete("/api/blocked/5.5.5.5")
        self.assertEqual(res.status_code, 200)
        data = json.loads(self.client.get("/api/blocked").data)
        ips = [r["ip_address"] for r in data]
        self.assertNotIn("5.5.5.5", ips)

    def test_unblock_not_blocked(self):
        res = self.client.delete("/api/blocked/9.9.9.9")
        self.assertEqual(res.status_code, 404)

    def test_unblock_invalid_ip(self):
        res = self.client.delete("/api/blocked/bad-ip")
        self.assertEqual(res.status_code, 400)


class TestAlertsAPI(unittest.TestCase):
    def setUp(self):
        self.app = _make_app()
        self.client = self.app.test_client()

    def test_alerts_empty(self):
        res = self.client.get("/api/alerts")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.data), [])


if __name__ == "__main__":
    unittest.main()
