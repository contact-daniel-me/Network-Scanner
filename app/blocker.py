"""
blocker.py – IP blocking via iptables with graceful fallback.

On Linux with root privileges the module inserts / deletes iptables rules.
In all other environments (non-Linux, insufficient privileges) it only logs
the intended action so the rest of the application can continue to work.
"""

import logging
import platform
import subprocess

logger = logging.getLogger(__name__)


def _can_use_iptables() -> bool:
    """Return True only on Linux when iptables is available and accessible."""
    if platform.system() != "Linux":
        return False
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n", "--line-numbers"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        return False


_IPTABLES_AVAILABLE = _can_use_iptables()


def block_ip(ip: str, reason: str = "") -> bool:
    """
    Block all incoming traffic from *ip*.

    Returns True when an iptables rule was successfully inserted, False when
    the system is running in log-only mode.
    """
    if not _IPTABLES_AVAILABLE:
        logger.info("[BLOCK-SIMULATED] Would block %s – %s", ip, reason)
        return False

    try:
        # Check whether a DROP rule for this IP already exists.
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            timeout=5,
        )
        if check.returncode == 0:
            logger.debug("iptables rule for %s already exists", ip)
            return True

        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        logger.info("[BLOCKED] %s – %s", ip, reason)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("iptables block failed for %s: %s", ip, exc.stderr)
        return False


def unblock_ip(ip: str) -> bool:
    """
    Remove the DROP rule for *ip*.

    Returns True when the rule was removed, False in log-only mode or on error.
    """
    if not _IPTABLES_AVAILABLE:
        logger.info("[UNBLOCK-SIMULATED] Would unblock %s", ip)
        return False

    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        logger.info("[UNBLOCKED] %s", ip)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("iptables unblock failed for %s: %s", ip, exc.stderr)
        return False
