"""
routes.py – Flask REST API blueprint.

Endpoints:
  GET  /                          – dashboard HTML
  GET  /api/traffic               – recent traffic logs
  GET  /api/stats                 – aggregate statistics
  GET  /api/stats/timeline        – packets-per-minute for last N minutes
  GET  /api/stats/protocols       – protocol distribution
  GET  /api/blocked               – currently blocked IPs
  POST /api/blocked               – manually block an IP
  DELETE /api/blocked/<ip>        – manually unblock an IP
  GET  /api/alerts                – recent alerts
"""

import re
import ipaddress
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, request

from app.database import (
    get_recent_traffic,
    get_traffic_stats,
    get_traffic_over_time,
    get_protocol_distribution,
    get_blocked_ips,
    block_ip as db_block_ip,
    unblock_ip as db_unblock_ip,
    is_ip_blocked,
    get_recent_alerts,
)
from app import blocker

bp = Blueprint("main", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@bp.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Traffic
# ---------------------------------------------------------------------------

@bp.route("/api/traffic")
def api_traffic():
    limit = min(int(request.args.get("limit", 100)), 500)
    rows = get_recent_traffic(current_app._get_current_object(), limit)
    return jsonify(rows)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@bp.route("/api/stats")
def api_stats():
    app = current_app._get_current_object()
    stats = get_traffic_stats(app)
    blocked_count = len(get_blocked_ips(app))
    stats["blocked_ips"] = blocked_count
    return jsonify(stats)


@bp.route("/api/stats/timeline")
def api_timeline():
    minutes = min(int(request.args.get("minutes", 10)), 60)
    data = get_traffic_over_time(current_app._get_current_object(), minutes)
    return jsonify(data)


@bp.route("/api/stats/protocols")
def api_protocols():
    data = get_protocol_distribution(current_app._get_current_object())
    return jsonify(data)


# ---------------------------------------------------------------------------
# Blocked IPs
# ---------------------------------------------------------------------------

@bp.route("/api/blocked", methods=["GET"])
def api_blocked_list():
    rows = get_blocked_ips(current_app._get_current_object())
    return jsonify(rows)


@bp.route("/api/blocked", methods=["POST"])
def api_block():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "Manual block").strip()

    if not ip or not _validate_ip(ip):
        return jsonify({"error": "Valid IP address required"}), 400

    app = current_app._get_current_object()

    if is_ip_blocked(app, ip):
        return jsonify({"error": f"{ip} is already blocked"}), 409

    ts = datetime.now(timezone.utc).isoformat()
    block_duration = app.config.get("BLOCK_DURATION", 3600)
    if block_duration > 0:
        from datetime import timedelta
        unblock_at = (
            datetime.now(timezone.utc) + timedelta(seconds=block_duration)
        ).isoformat()
    else:
        unblock_at = None

    db_block_ip(app, ip, reason, ts, unblock_at)
    blocker.block_ip(ip, reason)
    return jsonify({"message": f"{ip} blocked successfully"}), 201


@bp.route("/api/blocked/<path:ip>", methods=["DELETE"])
def api_unblock(ip: str):
    if not _validate_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    app = current_app._get_current_object()
    if not is_ip_blocked(app, ip):
        return jsonify({"error": f"{ip} is not currently blocked"}), 404

    db_unblock_ip(app, ip)
    blocker.unblock_ip(ip)
    return jsonify({"message": f"{ip} unblocked successfully"})


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@bp.route("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 50)), 200)
    rows = get_recent_alerts(current_app._get_current_object())
    return jsonify(rows[:limit])
