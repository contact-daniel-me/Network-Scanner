"""
scanner.py – Packet capture (Scapy) with simulation fallback.

The public entry-point is ``start_capture(app)``.  When the application is
configured with ``SIMULATION = True`` (the default) or Scapy cannot open a
raw socket, it falls back to an in-process traffic simulator that generates
realistic-looking packets including occasional port-scans and high-frequency
bursts so the dashboard is always populated.
"""

import logging
import random
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers shared by both paths
# ---------------------------------------------------------------------------

def _process_packet_info(app, packet_info: dict):
    """Run analysis, persist the result, and block if necessary."""
    from app import get_analyzer
    from app.database import (
        insert_traffic_log,
        insert_alert,
        block_ip as db_block_ip,
        is_ip_blocked,
        expire_blocks,
    )
    from app import blocker

    expire_blocks(app)

    analyzer = get_analyzer()
    src_ip = packet_info.get("src_ip", "")

    # Skip packets from already-blocked IPs (just log them as BLOCKED)
    if is_ip_blocked(app, src_ip):
        packet_info["action"] = "BLOCKED"
        insert_traffic_log(app, packet_info)
        return

    result = analyzer.analyze(packet_info)
    action = result["action"]
    threats = result["threats"]

    packet_info["action"] = action
    insert_traffic_log(app, packet_info)

    if threats:
        reason = ", ".join(threats)
        ts = datetime.now(timezone.utc).isoformat()
        insert_alert(app, {
            "timestamp": ts,
            "src_ip": src_ip,
            "alert_type": threats[0],
            "description": f"Threats detected: {reason}",
            "action_taken": action,
        })

        if action == "BLOCKED" and app.config.get("AUTO_BLOCK", True):
            block_duration = app.config.get("BLOCK_DURATION", 3600)
            if block_duration > 0:
                from datetime import timedelta
                unblock_at = (
                    datetime.now(timezone.utc) + timedelta(seconds=block_duration)
                ).isoformat()
            else:
                unblock_at = None

            db_block_ip(app, src_ip, reason, ts, unblock_at)
            blocker.block_ip(src_ip, reason)
            analyzer.reset(src_ip)


# ---------------------------------------------------------------------------
# Scapy-based live capture
# ---------------------------------------------------------------------------

def _scapy_callback(app):
    """Return a Scapy packet handler bound to *app*."""
    def handler(pkt):
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            if not pkt.haslayer(IP):
                return
            ip_layer = pkt[IP]
            proto = ip_layer.proto
            protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "OTHER")

            src_port = dst_port = None
            flags = None
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            packet_info = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": len(pkt),
                "flags": flags,
            }
            _process_packet_info(app, packet_info)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Error processing packet: %s", exc)

    return handler


def _start_scapy_capture(app):
    from scapy.sendrecv import sniff
    iface = app.config.get("INTERFACE")
    logger.info("Starting Scapy capture on interface %s", iface or "default")
    sniff(
        iface=iface,
        prn=_scapy_callback(app),
        store=False,
    )


# ---------------------------------------------------------------------------
# Simulation mode
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    "192.168.1.", "192.168.0.", "10.0.0.", "172.16.0.",
    "203.0.113.", "198.51.100.", "185.220.101.",
]

_COMMON_PORTS = [80, 443, 53, 8080, 8443, 22, 25, 587, 993, 3306, 5432]
_ATTACK_PORTS = [4444, 445, 3389, 1433, 6379, 9200, 27017]


def _random_ip() -> str:
    prefix = random.choice(_PRIVATE_NETS)
    return prefix + str(random.randint(1, 254))


def _simulate_normal_packet(src_ip: str) -> dict:
    proto = random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"])
    src_port = random.randint(1024, 65535)
    dst_port = random.choice(_COMMON_PORTS) if proto in ("TCP", "UDP") else None
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": _random_ip(),
        "protocol": proto,
        "src_port": src_port if proto in ("TCP", "UDP") else None,
        "dst_port": dst_port,
        "packet_size": random.randint(40, 1500),
        "flags": random.choice(["S", "SA", "A", "PA", "FA"]) if proto == "TCP" else None,
    }


def _simulate_port_scan(src_ip: str) -> list:
    """Return a rapid burst of packets to distinct ports (port scan)."""
    ports = random.sample(range(1, 65535), 15)
    return [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": _random_ip(),
            "protocol": "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": p,
            "packet_size": 44,
            "flags": "S",
        }
        for p in ports
    ]


def _simulate_high_frequency(src_ip: str, count: int = 120) -> list:
    """Return a rapid burst from one IP (DDoS / flood)."""
    return [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": _random_ip(),
            "protocol": "UDP",
            "src_port": random.randint(1024, 65535),
            "dst_port": 53,
            "packet_size": random.randint(28, 512),
            "flags": None,
        }
        for _ in range(count)
    ]


def _simulate_suspicious_port(src_ip: str) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": _random_ip(),
        "protocol": "TCP",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(_ATTACK_PORTS),
        "packet_size": random.randint(40, 200),
        "flags": "S",
    }


def _simulation_loop(app):
    rate = app.config.get("SIMULATION_RATE", 5)
    sleep = 1.0 / rate

    # Pool of "background" IPs producing normal traffic
    normal_ips = [_random_ip() for _ in range(20)]
    tick = 0

    logger.info("Simulation mode active – generating synthetic traffic")

    while True:
        tick += 1

        # Occasionally rotate in a fresh IP
        if tick % 50 == 0:
            normal_ips[random.randint(0, len(normal_ips) - 1)] = _random_ip()

        # Normal traffic
        src_ip = random.choice(normal_ips)
        _process_packet_info(app, _simulate_normal_packet(src_ip))

        # Every ~60 ticks: simulate a port scan from a new attacker
        if tick % 60 == 0:
            attacker = _random_ip()
            logger.debug("Simulating port scan from %s", attacker)
            for pkt in _simulate_port_scan(attacker):
                _process_packet_info(app, pkt)

        # Every ~90 ticks: simulate a high-frequency burst
        if tick % 90 == 0:
            attacker = _random_ip()
            logger.debug("Simulating high-frequency burst from %s", attacker)
            for pkt in _simulate_high_frequency(attacker):
                _process_packet_info(app, pkt)

        # Every ~30 ticks: suspicious-port probe
        if tick % 30 == 0:
            _process_packet_info(app, _simulate_suspicious_port(_random_ip()))

        time.sleep(sleep)


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def start_capture(app):
    """
    Start packet capture.  Tries Scapy first; falls back to simulation.
    Always called in a daemon thread so it dies with the main process.
    """
    simulation = app.config.get("SIMULATION", True)

    if not simulation:
        try:
            _start_scapy_capture(app)
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Scapy capture failed (%s); falling back to simulation.", exc
            )

    _simulation_loop(app)
