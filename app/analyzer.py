"""
analyzer.py – Sliding-window traffic analysis.

Detects:
  PORT_SCAN     – single source hitting many distinct destination ports
  HIGH_FREQUENCY – source sending packets far above the normal rate
  SUSPICIOUS_PORT – traffic to well-known attack / exfiltration ports
"""

import time
import threading
from collections import defaultdict

# Ports that are frequently targeted by malware, scanners, or data exfiltration.
SUSPICIOUS_PORTS = {
    22,    # SSH brute-force target
    23,    # Telnet
    445,   # SMB (ransomware, EternalBlue)
    1433,  # MSSQL
    3389,  # RDP brute-force
    4444,  # Metasploit default
    5900,  # VNC
    6379,  # Redis (unauthenticated exposure)
    9200,  # Elasticsearch (unauthenticated exposure)
    27017, # MongoDB (unauthenticated exposure)
}


class TrafficAnalyzer:
    """
    Thread-safe analyzer that keeps sliding-window state per source IP.

    Parameters
    ----------
    port_scan_threshold : int
        Number of unique destination ports within *port_scan_window* seconds
        that triggers a PORT_SCAN alert.
    port_scan_window : int
        Sliding window size in seconds for port-scan detection.
    high_freq_threshold : int
        Number of packets within *high_freq_window* seconds that triggers a
        HIGH_FREQUENCY alert.
    high_freq_window : int
        Sliding window size in seconds for high-frequency detection.
    """

    def __init__(
        self,
        port_scan_threshold: int = 10,
        port_scan_window: int = 10,
        high_freq_threshold: int = 100,
        high_freq_window: int = 5,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.high_freq_threshold = high_freq_threshold
        self.high_freq_window = high_freq_window

        self._lock = threading.Lock()
        # {ip: [(timestamp, dst_port), ...]}
        self._port_tracker: dict = defaultdict(list)
        # {ip: [timestamp, ...]}
        self._freq_tracker: dict = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, packet_info: dict) -> dict:
        """
        Analyse a single packet and return a result dict:
            {
              "action":  "ALLOWED" | "FLAGGED" | "BLOCKED",
              "threats": ["PORT_SCAN", ...],   # empty list if clean
            }
        """
        src_ip = packet_info.get("src_ip", "")
        dst_port = packet_info.get("dst_port")
        now = time.time()

        threats = []

        with self._lock:
            # --- high-frequency check ---
            freq = self._freq_tracker[src_ip]
            freq.append(now)
            # prune old entries
            cutoff = now - self.high_freq_window
            self._freq_tracker[src_ip] = [t for t in freq if t >= cutoff]
            if len(self._freq_tracker[src_ip]) >= self.high_freq_threshold:
                threats.append("HIGH_FREQUENCY")

            # --- port-scan check ---
            if dst_port is not None:
                ports = self._port_tracker[src_ip]
                ports.append((now, dst_port))
                cutoff = now - self.port_scan_window
                self._port_tracker[src_ip] = [(t, p) for t, p in ports if t >= cutoff]
                unique_ports = {p for _, p in self._port_tracker[src_ip]}
                if len(unique_ports) >= self.port_scan_threshold:
                    threats.append("PORT_SCAN")

        # --- suspicious-port check (stateless) ---
        if dst_port is not None and dst_port in SUSPICIOUS_PORTS:
            threats.append("SUSPICIOUS_PORT")

        if not threats:
            return {"action": "ALLOWED", "threats": []}

        # SUSPICIOUS_PORT alone → flag but allow; other threats → block.
        if threats == ["SUSPICIOUS_PORT"]:
            return {"action": "FLAGGED", "threats": threats}

        return {"action": "BLOCKED", "threats": threats}

    def reset(self, ip: str | None = None):
        """Clear tracking state (useful after blocking an IP)."""
        with self._lock:
            if ip:
                self._port_tracker.pop(ip, None)
                self._freq_tracker.pop(ip, None)
            else:
                self._port_tracker.clear()
                self._freq_tracker.clear()
