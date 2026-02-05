from flask import Flask, render_template, jsonify, request
import json
import os
from datetime import datetime, timezone
from config import config

app = Flask(__name__)

# Helper to read logs (reverse to get newest first)
def load_alerts(limit=100):
    alerts = []
    if os.path.exists(config.OUTPUT_ALERT_FILE):
        with open(config.OUTPUT_ALERT_FILE, 'r') as f:
            lines = f.readlines()
            # Get last 100 lines and reverse
            for line in reversed(lines[-limit:]): 
                if line.strip():
                    try:
                        alerts.append(json.loads(line))
                    except:
                        pass
    return alerts

def _read_all_alerts_newest_first():
    alerts = []
    if not os.path.exists(config.OUTPUT_ALERT_FILE):
        return alerts

    with open(config.OUTPUT_ALERT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except:
            pass
    return alerts

def _parse_ts_maybe(value: str):
    """
    Parse ISO timestamp to aware UTC datetime.
    Accepts:
      - '2026-01-30T10:20:30Z'
      - '2026-01-30T10:20:30+00:00'
      - '2026-01-30T10:20:30' (treated as UTC)
    """
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None

    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def _matches_filters(alert, severity=None, q=None, ip=None, mitre=None, from_ts=None, to_ts=None):
    # Time range
    if from_ts or to_ts:
        a_ts = _parse_ts_maybe(alert.get("timestamp"))
        if a_ts is None:
            return False
        if from_ts and a_ts < from_ts:
            return False
        if to_ts and a_ts > to_ts:
            return False

    # Severity
    if severity and str(alert.get("severity", "")).upper() != severity.upper():
        return False

    # IP
    if ip:
        a_ip = str(alert.get("ip_address", "") or "")
        if ip not in a_ip:
            return False

    # MITRE
    if mitre:
        a_mitre = str(alert.get("mitre_attck_id", "") or "")
        if mitre.upper() not in a_mitre.upper():
            return False

    # Free text
    if q:
        needle = q.lower()
        hay = " ".join([
            str(alert.get("alert_name", "") or ""),
            str(alert.get("description", "") or ""),
            str(alert.get("raw_log", "") or ""),
        ]).lower()
        if needle not in hay:
            return False

    return True

@app.route('/')
def dashboard():
    return render_template('dashboard.html', page='dashboard')

@app.route('/logs')
def logs():
    return render_template('logs.html', page='logs')

@app.route('/settings')
def settings():
    return render_template('settings.html', page='settings')

@app.route('/api/stats')
def api_stats():
    """API return basic stats for dashboard (real data)"""
    alerts = _read_all_alerts_newest_first()

    def count(sev):
        return sum(1 for a in alerts if str(a.get("severity", "")).upper() == sev)

    stats = {
        "critical": count("CRITICAL"),
        "high": count("HIGH"),
        "medium": count("MEDIUM"),
        "info": count("INFO"),
        "anomalies": sum(1 for a in alerts if "ml_anomaly_score" in a),
        "total": len(alerts),
    }
    return jsonify(stats)

@app.route('/api/alerts')
def api_alerts():
    """API return latest log list (for dashboard + live snippets)"""
    return jsonify(load_alerts(50))

@app.route("/api/alerts/search")
def api_alerts_search():
    """
    Server-side filtering + pagination for Logs page.
    Query params:
      - page (default 1)
      - page_size (default 50, max 200)
      - severity (CRITICAL/HIGH/MEDIUM/INFO)
      - q (free text: alert_name/description/raw_log)
      - ip (substring match)
      - mitre (substring match)
    """
    try:
        page = int(request.args.get("page", 1))
    except:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except:
        page_size = 50

    page = max(1, page)
    page_size = min(max(1, page_size), 200)

    severity = (request.args.get("severity") or "").strip() or None
    q = (request.args.get("q") or "").strip() or None
    ip = (request.args.get("ip") or "").strip() or None
    mitre = (request.args.get("mitre") or "").strip() or None

    from_ts = _parse_ts_maybe(request.args.get("from"))
    to_ts = _parse_ts_maybe(request.args.get("to"))

    alerts = _read_all_alerts_newest_first()
    filtered = [
        a for a in alerts
        if _matches_filters(a, severity=severity, q=q, ip=ip, mitre=mitre, from_ts=from_ts, to_ts=to_ts)
    ]

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    items = filtered[start:end]

    return jsonify({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size
    })

if __name__ == "__main__":
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=True)