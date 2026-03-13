"""
test_analyzer.py – Unit tests for the TrafficAnalyzer.
"""

import time
import unittest

from app.analyzer import TrafficAnalyzer, SUSPICIOUS_PORTS


def _pkt(src_ip="1.2.3.4", dst_port=80, protocol="TCP"):
    return {
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "protocol": protocol,
        "src_port": 12345,
        "dst_port": dst_port,
        "packet_size": 64,
        "flags": "S",
    }


class TestAnalyzerAllowed(unittest.TestCase):
    def setUp(self):
        self.a = TrafficAnalyzer(
            port_scan_threshold=10,
            port_scan_window=10,
            high_freq_threshold=100,
            high_freq_window=5,
        )

    def test_normal_packet_is_allowed(self):
        result = self.a.analyze(_pkt())
        self.assertEqual(result["action"], "ALLOWED")
        self.assertEqual(result["threats"], [])

    def test_different_ips_do_not_interfere(self):
        for i in range(15):
            self.a.analyze(_pkt(src_ip="1.1.1.1", dst_port=i + 1))
        result = self.a.analyze(_pkt(src_ip="2.2.2.2", dst_port=80))
        self.assertEqual(result["action"], "ALLOWED")


class TestPortScanDetection(unittest.TestCase):
    def setUp(self):
        self.a = TrafficAnalyzer(port_scan_threshold=5, port_scan_window=10)

    def test_port_scan_detected(self):
        for port in range(1, 6):
            result = self.a.analyze(_pkt(dst_port=port))
        self.assertIn("PORT_SCAN", result["threats"])
        self.assertEqual(result["action"], "BLOCKED")

    def test_repeated_same_port_not_scan(self):
        for _ in range(20):
            result = self.a.analyze(_pkt(dst_port=80))
        self.assertNotIn("PORT_SCAN", result["threats"])

    def test_reset_clears_state(self):
        for port in range(1, 6):
            self.a.analyze(_pkt(dst_port=port))
        self.a.reset("1.2.3.4")
        result = self.a.analyze(_pkt(dst_port=99))
        self.assertNotIn("PORT_SCAN", result["threats"])


class TestHighFrequencyDetection(unittest.TestCase):
    def setUp(self):
        self.a = TrafficAnalyzer(high_freq_threshold=5, high_freq_window=5)

    def test_high_frequency_detected(self):
        for _ in range(5):
            result = self.a.analyze(_pkt())
        self.assertIn("HIGH_FREQUENCY", result["threats"])
        self.assertEqual(result["action"], "BLOCKED")

    def test_below_threshold_allowed(self):
        for _ in range(4):
            result = self.a.analyze(_pkt())
        self.assertNotIn("HIGH_FREQUENCY", result["threats"])


class TestSuspiciousPortDetection(unittest.TestCase):
    def setUp(self):
        self.a = TrafficAnalyzer(
            port_scan_threshold=100,   # effectively disabled
            high_freq_threshold=100,
        )

    def test_suspicious_port_flagged(self):
        suspicious = next(iter(SUSPICIOUS_PORTS))
        result = self.a.analyze(_pkt(dst_port=suspicious))
        self.assertIn("SUSPICIOUS_PORT", result["threats"])
        # Suspicious port alone → FLAGGED, not BLOCKED
        self.assertEqual(result["action"], "FLAGGED")

    def test_normal_port_not_flagged(self):
        result = self.a.analyze(_pkt(dst_port=80))
        self.assertNotIn("SUSPICIOUS_PORT", result["threats"])

    def test_suspicious_port_constants(self):
        # Ensure the set contains the expected high-risk ports.
        self.assertIn(445,   SUSPICIOUS_PORTS)   # SMB
        self.assertIn(3389,  SUSPICIOUS_PORTS)   # RDP
        self.assertIn(4444,  SUSPICIOUS_PORTS)   # Metasploit


class TestResetAll(unittest.TestCase):
    def test_global_reset(self):
        a = TrafficAnalyzer(port_scan_threshold=3, high_freq_threshold=3)
        for i in range(3):
            a.analyze(_pkt(dst_port=i + 1))
        a.reset()   # reset all IPs
        result = a.analyze(_pkt(dst_port=99))
        self.assertNotIn("PORT_SCAN", result["threats"])


if __name__ == "__main__":
    unittest.main()
