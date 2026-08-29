import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from io import BytesIO
import hashlib
import re
from pathlib import Path

from flask import Flask, render_template, jsonify, redirect, request, send_file, session, url_for

from config import config
from src.alert_schema import INCIDENT_STATUSES, utc_iso
from src.assets import CRITICALITIES, ENVIRONMENTS, build_asset
from src.audit import append_audit_event, verify_audit_log
from src.case_connector import CaseExportService
from src.health import build_system_status
from src.incident_report import generate_incident_pdf
from src.ingestion_failures import (
    get_ingestion_failure_diagnostics, get_ingestion_health_metrics,
    record_collector_heartbeat,
)
from src.jira import JiraConnector
from src.metrics import metrics_unavailable, render_prometheus_metrics
from src.dashboard_auth import (
    authenticate,
    clear_login_failures,
    csrf_token,
    csrf_valid,
    delete_user,
    get_user,
    init_auth,
    init_proxy,
    login_allowed,
    load_users,
    record_login_failure,
    role_required,
    save_user,
    user_auth_version,
)
from src.alert_store import (
    add_analyst_note,
    approve_response_action,
    request_response_action,
    rollback_response_action,
    update_assignee,
    update_incident_status,
)
from src.rules import build_detection_coverage, load_detection_rules
from src.sigma import load_sigma_rules, set_sigma_rule_enabled
from src.storage import alert_repository
from src.sqlite_store import SQLiteAssetRepository
from src.thehive import TheHiveConnector
from src.windows_events import ingest_windows_events

app = Flask(__name__)
init_proxy(app)
init_auth(app)

RUNTIME_SETTINGS_FILE = os.path.join(config.BASE_DIR, "data", "runtime_settings.json")
VALIDATION_COVERAGE_FILE = Path(config.BASE_DIR, "docs", "DETECTION_VALIDATION_COVERAGE.json")
DETECTION_RULES = load_detection_rules(
    config.RULES_DIR, config.SIGNATURES, config.SIGMA_RULES_DIR,
)
SIGMA_RULES, _ = load_sigma_rules(config.SIGMA_RULES_DIR)
RULES_LOADED_AT = utc_iso()
asset_repository = SQLiteAssetRepository()
case_connector = None
if config.CASE_EXPORT_PROVIDER == "thehive" and config.THEHIVE_URL and config.THEHIVE_API_KEY:
    case_connector = TheHiveConnector(config.THEHIVE_URL, config.THEHIVE_API_KEY)
elif config.CASE_EXPORT_PROVIDER == "jira" and all((
    config.JIRA_URL, config.JIRA_USER_EMAIL,
    config.JIRA_API_TOKEN, config.JIRA_PROJECT_KEY,
)):
    case_connector = JiraConnector(
        config.JIRA_URL, config.JIRA_USER_EMAIL, config.JIRA_API_TOKEN,
        config.JIRA_PROJECT_KEY, config.JIRA_ISSUE_TYPE,
    )
case_export_service = CaseExportService(
    case_connector,
    enabled=config.CASE_EXPORT_ENABLED,
    timeout_seconds=config.CASE_EXPORT_TIMEOUT_SECONDS,
    max_attempts=config.CASE_EXPORT_MAX_ATTEMPTS,
)

ALLOWED_SETTINGS = {
    "NIDS_ENABLED",
    "HONEYPOT_ENABLED",
    "GRAPH_AUTO_REFRESH",
    "GRAPH_REFRESH_MS",
    "GRAPH_MAX_ALERTS",
    "GRAPH_INCLUDE_SOURCES",
    "GRAPH_INCLUDE_CAMPAIGNS",
}

def _ensure_runtime_settings_file():
    os.makedirs(os.path.dirname(RUNTIME_SETTINGS_FILE), exist_ok=True)
    if not os.path.exists(RUNTIME_SETTINGS_FILE):
        with open(RUNTIME_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

def load_runtime_settings() -> dict:
    _ensure_runtime_settings_file()
    try:
        with open(RUNTIME_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def save_runtime_settings(patch: dict) -> dict:
    _ensure_runtime_settings_file()
    current = load_runtime_settings()
    current.update(patch)
    with open(RUNTIME_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)
    return current

def _effective_settings() -> dict:
    runtime = load_runtime_settings()
    # Defaults from config + overrides from runtime file
    eff = {
        "NIDS_ENABLED": bool(getattr(config, "NIDS_ENABLED", False)),
        "HONEYPOT_ENABLED": bool(getattr(config, "HONEYPOT_ENABLED", False)),
        "GRAPH_AUTO_REFRESH": bool(getattr(config, "GRAPH_AUTO_REFRESH", True)),
        "GRAPH_REFRESH_MS": int(getattr(config, "GRAPH_REFRESH_MS", 10000)),
        "GRAPH_MAX_ALERTS": int(getattr(config, "GRAPH_MAX_ALERTS", 500)),
        "GRAPH_INCLUDE_SOURCES": bool(getattr(config, "GRAPH_INCLUDE_SOURCES", True)),
        "GRAPH_INCLUDE_CAMPAIGNS": bool(getattr(config, "GRAPH_INCLUDE_CAMPAIGNS", True)),
    }
    for k, v in (runtime or {}).items():
        if k in ALLOWED_SETTINGS:
            eff[k] = v
    # normalize
    eff["GRAPH_REFRESH_MS"] = max(1000, int(eff.get("GRAPH_REFRESH_MS") or 10000))
    eff["GRAPH_MAX_ALERTS"] = max(50, int(eff.get("GRAPH_MAX_ALERTS") or 500))
    return eff

# Helper to read logs (reverse to get newest first)
def load_alerts(limit=100):
    return alert_repository.list_alerts(limit=limit)


def _reload_detection_rules():
    global DETECTION_RULES, SIGMA_RULES, RULES_LOADED_AT
    DETECTION_RULES = load_detection_rules(
        config.RULES_DIR, config.SIGNATURES, config.SIGMA_RULES_DIR,
    )
    SIGMA_RULES, _ = load_sigma_rules(config.SIGMA_RULES_DIR)
    RULES_LOADED_AT = utc_iso()


def _detection_rule_records() -> list[dict]:
    rules = [
        rule for rule in DETECTION_RULES if rule.get("rule_source", "native") == "native"
    ] + SIGMA_RULES
    counts = alert_repository.rule_hit_counts([rule["id"] for rule in rules])
    return [{
        "rule_id": rule["id"],
        "title": rule["title"],
        "rule_source": rule.get("rule_source", "native"),
        "enabled": rule["enabled"],
        "supported": rule.get("supported", True),
        "validation_status": rule.get("validation_status", "valid"),
        "last_loaded_at": rule.get("last_loaded_at", RULES_LOADED_AT),
        "hit_count": int(counts.get(rule["id"], 0)),
        "never_hit": int(counts.get(rule["id"], 0)) == 0,
        "skip_reason": rule.get("skip_reason"),
        "mitre_tactic": (rule.get("mitre") or {}).get("tactic", "Unmapped"),
        "mitre_technique": (rule.get("mitre") or {}).get("technique", "Unmapped"),
    } for rule in rules]


def _rule_quality_with_validation(rows: list[dict]) -> list[dict]:
    quality = {row["rule_id"]: row for row in rows}
    try:
        artifact = json.loads(VALIDATION_COVERAGE_FILE.read_text(encoding="utf-8"))
        validation_rules = artifact.get("rules", [])
        if not isinstance(validation_rules, list):
            raise ValueError("validation rules must be a list")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        validation_rules = []

    for validation in validation_rules:
        if not isinstance(validation, dict) or not isinstance(validation.get("rule_id"), str):
            continue
        rule_id = validation["rule_id"].strip()
        if not rule_id or len(rule_id) > 200:
            continue
        scenario_count = validation.get("scenario_count")
        if isinstance(scenario_count, bool) or not isinstance(scenario_count, int):
            scenario_count = 0
        validation_result = str(validation.get("last_validation_result") or "").upper()
        if validation_result not in {"PASS", "FAIL", "UNVALIDATED"}:
            validation_result = "UNAVAILABLE"
        row = quality.setdefault(rule_id, {
            "rule_id": rule_id,
            "alerts_generated": 0,
            "true_positives": 0,
            "false_positives": 0,
            "benign_expected": 0,
            "unclassified": 0,
            "classified_sample_size": 0,
            "false_positive_rate_percent": None,
        })
        row["validation_scenario_count"] = max(0, scenario_count)
        row["last_validation_result"] = validation_result

    for row in quality.values():
        row.setdefault("validation_scenario_count", 0)
        row.setdefault("last_validation_result", "UNAVAILABLE")
    return sorted(quality.values(), key=lambda row: (-row["alerts_generated"], row["rule_id"]))


def _detection_tuning_payload() -> dict:
    rules = _detection_rule_records()
    quality = {
        row["rule_id"]: row for row in _rule_quality_with_validation(
            alert_repository.rule_quality("1970-01-01T00:00:00Z", utc_iso())
        )
    }
    exceptions = [
        record for record in alert_repository.list_detection_exceptions() if record["active"]
    ]
    policies = alert_repository.list_alert_suppression_policies()
    exceptions_by_rule = defaultdict(list)
    policies_by_rule = defaultdict(list)
    for record in exceptions:
        if record["scope_type"] == "rule_id":
            exceptions_by_rule[record["scope_value"]].append(record)
    for policy in policies:
        policies_by_rule[policy["rule_id"]].append(policy)
    for rule in rules:
        rule["feedback"] = quality.get(rule["rule_id"], {
            "alerts_generated": rule["hit_count"],
            "true_positives": 0,
            "false_positives": 0,
            "benign_expected": 0,
            "unclassified": rule["hit_count"],
            "classified_sample_size": 0,
            "false_positive_rate_percent": None,
            "validation_scenario_count": 0,
            "last_validation_result": "UNAVAILABLE",
        })
        rule["exceptions"] = exceptions_by_rule[rule["rule_id"]]
        rule["suppression_policies"] = policies_by_rule[rule["rule_id"]]
    return {"rules": rules, "active_exceptions": exceptions}


def _directory_status(path, pattern):
    try:
        files = sorted(
            (item for item in Path(path).glob(pattern) if item.is_file()),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        latest = files[0] if files else None
        return {
            "count": len(files),
            "latest": latest.name if latest else None,
            "latest_at": utc_iso(datetime.fromtimestamp(latest.stat().st_mtime, timezone.utc)) if latest else None,
        }
    except OSError as exc:
        return {"count": 0, "latest": None, "latest_at": None, "error": type(exc).__name__}


def _admin_workspace_payload():
    health = build_system_status(_effective_settings())
    audit_valid, audit_message = verify_audit_log()
    try:
        with Path(config.ANALYST_AUDIT_FILE).open(encoding="utf-8") as audit_file:
            audit_events = sum(1 for line in audit_file if line.strip())
    except OSError:
        audit_events = 0
    database = Path(config.SQLITE_ALERT_DB)
    try:
        database_status = {
            "exists": database.is_file(),
            "size_bytes": database.stat().st_size if database.is_file() else 0,
        }
    except OSError as exc:
        database_status = {"exists": False, "size_bytes": 0, "error": type(exc).__name__}
    users = [
        {"username": username, "role": record.get("role")}
        for username, record in sorted(load_users().items())
        if isinstance(record, dict) and record.get("role") in {"viewer", "analyst", "admin"}
    ]
    ai = health.get("ai") or {}
    ti_providers = [
        name for name, configured in (
            ("GeoIP", config.GEOIP_ENABLED),
            ("AbuseIPDB", bool(config.ABUSEIPDB_API_KEY)),
            ("VirusTotal", bool(config.VIRUSTOTAL_API_KEY)),
            ("STIX", bool(config.STIX_BUNDLE_FILE)),
            ("TAXII", bool(config.TAXII_COLLECTION_URL)),
        ) if configured
    ]
    external_ready = case_connector is not None
    integrations = [
        {
            "name": "External case",
            "status": "ready" if config.CASE_EXPORT_ENABLED and external_ready else "disabled" if not config.CASE_EXPORT_ENABLED else "needs_configuration",
            "detail": config.CASE_EXPORT_PROVIDER,
        },
        {
            "name": "AI analyst",
            "status": "ready" if ai.get("enabled") and ai.get("available") is not False else "disabled" if not ai.get("enabled") else "unavailable",
            "detail": str(ai.get("provider") or config.AI_PROVIDER),
        },
        {
            "name": "Threat intelligence",
            "status": "ready" if ti_providers else "disabled",
            "detail": ", ".join(ti_providers) or "No provider configured",
        },
        {
            "name": "Notifications",
            "status": "ready" if bool(config.NOTIFICATION_WEBHOOK_URL) else "disabled",
            "detail": config.NOTIFICATION_WEBHOOK_FORMAT,
        },
        {
            "name": "Windows collector",
            "status": "ready" if bool(config.WINDOWS_COLLECTOR_SECRET) else "disabled",
            "detail": "Shared secret configured" if config.WINDOWS_COLLECTOR_SECRET else "Not configured",
        },
    ]
    ingestion_failures = get_ingestion_failure_diagnostics()
    return {
        "current_username": session["username"],
        "users": users,
        "health": health,
        "integrations": integrations,
        "audit": {"valid": audit_valid, "message": audit_message, "events": audit_events},
        "ingestion_failures": ingestion_failures,
        "maintenance": {
            "retention_days": config.ALERT_RETENTION_DAYS,
            "log_rotate_max_bytes": config.LOG_ROTATE_MAX_BYTES,
            "log_rotate_backups": config.LOG_ROTATE_BACKUPS,
            "database": database_status,
            "backups": _directory_status(config.SQLITE_BACKUP_DIR, "*.db"),
            "archives": _directory_status(config.ALERT_ARCHIVE_DIR, "*.jsonl"),
        },
    }

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


def _auth_error():
    if request.path.startswith("/api/"):
        return jsonify({"error": "Authentication required"}), 401
    return redirect(url_for("login", next=request.full_path.rstrip("?")))


@app.before_request
def require_dashboard_authentication():
    if request.endpoint in {"login", "static", "api_windows_events", "health", "metrics"}:
        return None
    username = session.get("username")
    user = get_user(username) if username else None
    if not user or not hmac.compare_digest(
        str(session.get("auth_version", "")), user_auth_version(user)
    ):
        session.clear()
        return _auth_error()
    session["role"] = user["role"]
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not csrf_valid():
        return jsonify({"error": "Invalid CSRF token"}), 400
    return None


@app.context_processor
def authentication_context():
    return {
        "csrf_token": csrf_token,
        "current_username": session.get("username"),
        "current_role": session.get("role"),
    }


@app.after_request
def dashboard_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if request.endpoint != "static":
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("username") and get_user(session["username"]):
            return redirect(url_for("dashboard"))
        return render_template("login.html", error=None, next=request.args.get("next", ""))

    if not csrf_valid():
        return render_template("login.html", error="Invalid login request.", next=""), 400
    key = request.remote_addr or "unknown"
    if not login_allowed(key):
        append_audit_event("LOGIN", request.form.get("username", "unknown"), outcome="BLOCKED")
        return render_template("login.html", error="Too many attempts. Try again in one minute.", next=""), 429
    username, user = authenticate(request.form.get("username", ""), request.form.get("password", ""))
    if not user:
        record_login_failure(key)
        append_audit_event("LOGIN", request.form.get("username", "unknown"), outcome="DENIED")
        return render_template("login.html", error="Invalid username or password.", next=request.form.get("next", "")), 401

    clear_login_failures(key)
    destination = request.form.get("next", "")
    if not destination.startswith("/") or destination.startswith("//"):
        destination = url_for("dashboard")
    session.clear()
    session.update(
        username=username,
        role=user["role"],
        auth_version=user_auth_version(user),
        csrf_token=os.urandom(32).hex(),
    )
    session.permanent = True
    append_audit_event("LOGIN", username, role=user["role"])
    return redirect(destination)


@app.route("/logout", methods=["POST"])
def logout():
    append_audit_event("LOGOUT", session["username"], role=session.get("role"))
    session.clear()
    return redirect(url_for("login"))

@app.route('/')
def dashboard():
    return render_template('dashboard.html', page='dashboard')


@app.route('/analytics')
def analytics():
    return render_template('analytics.html', page='analytics')


@app.route("/health")
def health():
    status = build_system_status(_effective_settings())
    public = {
        "status": status["status"],
        "timestamp": status["timestamp"],
        "dashboard": status["dashboard"]["status"],
        "agent": status["agent"]["status"],
        "alert_store": status["alert_store"]["status"],
        "database": status["database"]["status"],
        "ingestion": status["ingestion"]["status"],
        "ingestion_queue": status["ingestion_queue"]["status"],
    }
    return jsonify(public), 503 if status["status"] == "unhealthy" else 200


@app.route("/metrics")
def metrics():
    expected = config.METRICS_BEARER_TOKEN
    supplied = request.headers.get("Authorization", "")
    if expected and not hmac.compare_digest(supplied, f"Bearer {expected}"):
        return app.response_class(
            "Authentication required\n", status=401,
            headers={"WWW-Authenticate": "Bearer"}, content_type="text/plain; charset=utf-8",
        )
    try:
        body = render_prometheus_metrics(
            alert_repository.list_alerts(),
            _detection_rule_records(),
            build_system_status(_effective_settings()),
            config.NOTIFICATION_LOG_FILE,
            get_ingestion_failure_diagnostics(limit=0)["counts"],
            get_ingestion_health_metrics(),
        )
        status = 200
    except Exception:
        body, status = metrics_unavailable(), 503
    return app.response_class(
        body, status=status,
        content_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.route("/api/system/status")
@role_required("admin")
def api_system_status():
    status = build_system_status(_effective_settings())
    return jsonify(status), 503 if status["status"] == "unhealthy" else 200


@app.route("/api/analytics/kpis")
def api_soc_kpis():
    raw_from, raw_to = request.args.get("from"), request.args.get("to")
    to_timestamp = _parse_ts_maybe(raw_to) if raw_to else datetime.now(timezone.utc)
    from_timestamp = _parse_ts_maybe(raw_from) if raw_from else to_timestamp - timedelta(hours=24)
    if (raw_from and from_timestamp is None) or (raw_to and to_timestamp is None):
        return jsonify({"error": "from and to must be ISO-8601 timestamps"}), 400
    if from_timestamp >= to_timestamp:
        return jsonify({"error": "from must be earlier than to"}), 400
    if to_timestamp - from_timestamp > timedelta(days=366):
        return jsonify({"error": "KPI range must not exceed 366 days"}), 400
    period = {"from": utc_iso(from_timestamp), "to": utc_iso(to_timestamp)}
    try:
        kpis = alert_repository.soc_kpis(period["from"], period["to"])
        analytics = alert_repository.soc_analytics(period["from"], period["to"])
        analytics["rule_quality"] = _rule_quality_with_validation(
            alert_repository.rule_quality(period["from"], period["to"])
        )
    except Exception:
        return jsonify({"error": "Analytics data unavailable"}), 503
    return jsonify({
        "period": {**period, "boundary": "[from,to)", "timestamp": "alert.created_at"},
        "definitions": {
            "mttd_seconds": "alert.timestamp to alert.created_at",
            "mtta_seconds": "incident.created_at to first analyst workflow event",
            "mttr_seconds": "incident.created_at to first RESOLVED transition",
            "false_positive_rate_percent": "FALSE_POSITIVE / (RESOLVED + FALSE_POSITIVE)",
            "human_review_rate_percent": "REQUIRES_HUMAN_REVIEW alerts / alerts",
            "ai_enrichment_success_rate_percent": "successful / completed AI enrichments",
            "rule_quality_false_positive_rate_percent": (
                "latest FALSE_POSITIVE feedback / alerts with any latest feedback"
            ),
            "rule_quality_unclassified": "alerts without analyst feedback",
        },
        "kpis": kpis,
        "analytics": analytics,
    })

@app.route('/logs')
def logs():
    return render_template('logs.html', page='logs')


@app.route('/detections')
@role_required("analyst")
def detections():
    return render_template('detections.html', page='detections')


@app.route('/api/detection-tuning')
@role_required("analyst")
def api_detection_tuning():
    try:
        return jsonify(_detection_tuning_payload())
    except Exception:
        return jsonify({"error": "Detection tuning data unavailable"}), 503

@app.route('/settings')
@role_required("admin")
def settings():
    return render_template(
        'settings.html',
        page='settings',
        log_path=config.LOG_FILE_TO_WATCH,
        alerts_path=config.OUTPUT_ALERT_FILE,
    )

@app.route("/api/settings")
@role_required("admin")
def api_settings_get():
    return jsonify(_effective_settings())


@app.route("/api/admin/workspace")
@role_required("admin")
def api_admin_workspace():
    return jsonify(_admin_workspace_payload())


@app.route("/api/admin/users", methods=["POST"])
@role_required("admin")
def api_admin_user_save():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "JSON body must be an object"}), 400
    username = str(body.get("username") or "").strip().lower()
    role = str(body.get("role") or "").strip().lower()
    if username == session["username"] and role != "admin":
        return jsonify({"error": "The active admin account cannot be demoted"}), 400
    try:
        existed = save_user(
            username,
            body.get("password"),
            role,
            audit=lambda existed: append_audit_event(
                "USER_UPDATED" if existed else "USER_CREATED",
                session["username"], role=session.get("role"),
                target_type="dashboard_user", target_id=username,
                details={"assigned_role": role},
            ),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503
    return jsonify({"username": username, "role": role}), 200 if existed else 201


@app.route("/api/admin/users/<username>", methods=["DELETE"])
@role_required("admin")
def api_admin_user_delete(username):
    normalized = str(username).strip().lower()
    if normalized == session["username"]:
        return jsonify({"error": "The active admin account cannot be deleted"}), 400
    try:
        deleted = delete_user(
            normalized,
            audit=lambda: append_audit_event(
                "USER_DELETED", session["username"], role=session.get("role"),
                target_type="dashboard_user", target_id=normalized,
            ),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503
    if not deleted:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/detection-exceptions", methods=["GET", "POST"])
@role_required("admin")
def api_detection_exceptions():
    if request.method == "GET":
        return jsonify({"exceptions": alert_repository.list_detection_exceptions()})
    if request.content_length and request.content_length > 8 * 1024:
        return jsonify({"error": "Detection exception request exceeds 8 KiB"}), 413
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400
    unknown = set(body) - {"scope_type", "scope_value", "reason", "expires_at"}
    if unknown:
        return jsonify({"error": f"Unsupported exception fields: {', '.join(sorted(unknown))}"}), 400
    try:
        record = alert_repository.create_detection_exception(
            body.get("scope_type"), body.get("scope_value"), body.get("reason"),
            session["username"], session.get("role"), body.get("expires_at"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(record), 201


@app.route("/api/detection-exceptions/<exception_id>", methods=["DELETE"])
@role_required("admin")
def api_detection_exception_delete(exception_id):
    try:
        deleted = alert_repository.delete_detection_exception(
            exception_id, session["username"], session.get("role"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not deleted:
        return jsonify({"error": "Detection exception not found"}), 404
    return "", 204


@app.route("/api/alert-suppression-policies", methods=["GET", "POST"])
@role_required("admin")
def api_alert_suppression_policies():
    if request.method == "GET":
        return jsonify({"policies": alert_repository.list_alert_suppression_policies()})
    if request.content_length and request.content_length > 8 * 1024:
        return jsonify({"error": "Suppression policy request exceeds 8 KiB"}), 413
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400
    unknown = set(body) - {"rule_id", "correlation_key", "window_seconds"}
    if unknown:
        return jsonify({"error": f"Unsupported policy fields: {', '.join(sorted(unknown))}"}), 400
    try:
        policy = alert_repository.create_alert_suppression_policy(
            body.get("rule_id"), body.get("correlation_key"), body.get("window_seconds"),
            session["username"], session.get("role"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(policy), 201


@app.route("/api/alert-suppression-policies/<policy_id>", methods=["DELETE"])
@role_required("admin")
def api_alert_suppression_policy_delete(policy_id):
    try:
        deleted = alert_repository.delete_alert_suppression_policy(
            policy_id, session["username"], session.get("role"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not deleted:
        return jsonify({"error": "Alert suppression policy not found"}), 404
    return "", 204

@app.route("/api/settings/update", methods=["POST"])
@role_required("admin")
def api_settings_update():
    body = request.get_json(silent=True) or {}
    patch = {}
    for k, v in body.items():
        if k not in ALLOWED_SETTINGS:
            continue
        patch[k] = v
    previous = load_runtime_settings()
    saved = save_runtime_settings(patch)
    if patch:
        append_audit_event(
            "RUNTIME_SETTING_CHANGED", session["username"], role=session.get("role"),
            target_type="runtime_settings",
            details={key: {"from": previous.get(key), "to": value} for key, value in patch.items()},
        )
    return jsonify({"ok": True, "saved": saved, "effective": _effective_settings()})

@app.route('/api/stats')
def api_stats():
    """API return basic stats for dashboard (real data)"""
    return jsonify(alert_repository.stats())


@app.route('/api/detection-coverage')
def api_detection_coverage():
    rule_ids = [rule["id"] for rule in DETECTION_RULES]
    return jsonify(build_detection_coverage(
        DETECTION_RULES,
        alert_repository.rule_hit_counts(rule_ids),
    ))


@app.route("/api/detection-rules")
@role_required("admin")
def api_detection_rules():
    return jsonify({"rules": _detection_rule_records()})


@app.route("/api/detection-rules/<rule_id>", methods=["PATCH"])
@role_required("admin")
def api_detection_rule_update(rule_id):
    body = request.get_json(silent=True) or {}
    if not isinstance(body.get("enabled"), bool):
        return jsonify({"error": "enabled must be boolean"}), 400
    try:
        set_sigma_rule_enabled(rule_id, body["enabled"], session["username"])
        _reload_detection_rules()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    rule = next(item for item in _detection_rule_records() if item["rule_id"] == rule_id)
    return jsonify(rule)

@app.route('/api/alerts')
def api_alerts():
    """API return latest log list (for dashboard + live snippets)"""
    return jsonify(load_alerts(50))


@app.route("/api/alerts/<alert_id>/report.pdf")
def api_incident_report(alert_id):
    alert = alert_repository.get_alert(alert_id)
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    try:
        report = generate_incident_pdf(alert)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    filename = re.sub(r"[^A-Za-z0-9._-]", "_", str(alert["incident_id"]))[:120]
    return send_file(
        BytesIO(report), mimetype="application/pdf", as_attachment=True,
        download_name=f"{filename}.pdf", max_age=0,
    )


@app.route("/api/alerts/<alert_id>/external-case", methods=["POST"])
@role_required("analyst")
def api_external_case(alert_id):
    try:
        result = case_export_service.export(
            alert_repository, alert_id,
            actor=session["username"], role=session.get("role"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if result is None:
        return jsonify({"error": "Alert not found"}), 404
    status_code = {
        "EXPORTED": 201,
        "DEDUPLICATED": 200,
        "DISABLED": 503,
        "MISCONFIGURED": 503,
        "FAILED": 502,
    }[result["status"]]
    return jsonify(result), status_code


@app.route("/api/windows-events", methods=["POST"])
def api_windows_events():
    expected = config.WINDOWS_COLLECTOR_SECRET
    if not expected:
        return jsonify({"error": "Windows collector ingestion is disabled"}), 503
    supplied = request.headers.get("X-Mini-SIEM-Secret", "")
    if not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "Unauthorized"}), 401
    if request.content_length and request.content_length > 2 * 1024 * 1024:
        return jsonify({"error": "Windows event batch is too large"}), 413

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    events = body.get("events")
    heartbeat = body.get("heartbeat", False)
    endpoint_available = body.get("endpoint_available", True)
    if not isinstance(events, list) or (not events and heartbeat is not True):
        return jsonify({"error": "events must be a non-empty list unless heartbeat is true"}), 400
    if not isinstance(heartbeat, bool) or not isinstance(endpoint_available, bool):
        return jsonify({"error": "heartbeat and endpoint_available must be boolean"}), 400
    if len(events) > 500:
        return jsonify({"error": "Windows event batch exceeds 500 events"}), 413
    collector_id = body.get("collector_id") or body.get("source") or "windows-collector"
    try:
        summary = (
            ingest_windows_events(events, collector_id)
            if events else {"read": 0, "imported": 0, "duplicates": 0, "unsupported": 0, "errors": 0}
        )
        record_collector_heartbeat(
            collector_id,
            events_received=len(events),
            endpoint_available=endpoint_available,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Could not persist Windows collector heartbeat")
        return jsonify({"error": "Windows collector heartbeat unavailable"}), 503
    collector_status = (
        "endpoint_unavailable" if not endpoint_available
        else "healthy" if events
        else "idle"
    )
    return jsonify({"ok": True, "collector_status": collector_status, **summary})


@app.route("/api/alerts/<alert_id>/status", methods=["PATCH"])
@role_required("analyst")
def api_alert_status(alert_id):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    if not isinstance(status, str) or status.upper() not in INCIDENT_STATUSES:
        return jsonify({"error": "Invalid incident status"}), 400
    try:
        alert = update_incident_status(alert_id, status.upper())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    event = alert["timeline"][-1]
    append_audit_event(
        "STATUS_CHANGED", session["username"], role=session.get("role"),
        target_type="incident", target_id=alert["incident_id"],
        details={"from": event["from_status"], "to": event["to_status"]},
    )
    return jsonify(alert)


@app.route("/assets")
@role_required("admin")
def assets():
    return render_template("assets.html", page="assets")


def _asset_request_body():
    if request.content_length and request.content_length > 64 * 1024:
        raise ValueError("Asset request exceeds 64 KiB")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object")
    return body


def _asset_error(exc):
    message = str(exc)
    status = 409 if "duplicate" in message.lower() or "already exists" in message.lower() else 400
    return jsonify({"error": message}), status


@app.route("/api/assets", methods=["GET", "POST"])
@role_required("admin")
def api_assets():
    if request.method == "POST":
        try:
            body = _asset_request_body()
            allowed = {
                "hostname", "ip_addresses", "os", "owner", "department",
                "environment", "criticality", "tags", "enabled",
            }
            unknown = set(body) - allowed
            if unknown:
                raise ValueError(f"Unsupported asset fields: {', '.join(sorted(unknown))}")
            if "hostname" not in body:
                raise ValueError("hostname is required")
            asset = build_asset(**body)
            created = asset_repository.create_asset(
                asset, actor=session["username"], role=session.get("role"),
            )
            return jsonify(created), 201
        except (TypeError, ValueError) as exc:
            return _asset_error(exc)

    q = (request.args.get("q") or "").strip().casefold()
    environment = (request.args.get("environment") or "").strip().lower()
    criticality = (request.args.get("criticality") or "").strip().upper()
    enabled_text = (request.args.get("enabled") or "").strip().lower()
    if len(q) > 200:
        return jsonify({"error": "Search query exceeds 200 characters"}), 400
    if environment and environment not in ENVIRONMENTS:
        return jsonify({"error": "Invalid environment filter"}), 400
    if criticality and criticality not in CRITICALITIES:
        return jsonify({"error": "Invalid criticality filter"}), 400
    if enabled_text not in {"", "true", "false"}:
        return jsonify({"error": "enabled filter must be true or false"}), 400

    enabled = None if not enabled_text else enabled_text == "true"
    assets = asset_repository.list_assets(enabled=enabled)
    # ponytail: in-memory filtering fits the single-node lab; move to SQL if inventory reaches thousands.
    if environment:
        assets = [asset for asset in assets if asset["environment"] == environment]
    if criticality:
        assets = [asset for asset in assets if asset["criticality"] == criticality]
    if q:
        assets = [asset for asset in assets if q in " ".join([
            asset["asset_id"], asset["hostname"], *asset["ip_addresses"], asset["os"], asset["owner"],
            asset["department"], *asset["tags"],
        ]).casefold()]
    return jsonify({"assets": assets, "total": len(assets)})


@app.route("/api/assets/<asset_id>", methods=["GET", "PATCH", "DELETE"])
@role_required("admin")
def api_asset(asset_id):
    if request.method == "GET":
        asset = asset_repository.get_asset(asset_id)
        return (jsonify(asset), 200) if asset else (jsonify({"error": "Asset not found"}), 404)
    if request.method == "DELETE":
        deleted = asset_repository.delete_asset(
            asset_id, actor=session["username"], role=session.get("role"),
        )
        return ("", 204) if deleted else (jsonify({"error": "Asset not found"}), 404)

    try:
        changes = _asset_request_body()
        allowed = {
            "hostname", "ip_addresses", "os", "owner", "department",
            "environment", "criticality", "tags", "enabled",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"Unsupported asset fields: {', '.join(sorted(unknown))}")
        if not changes:
            raise ValueError("At least one asset field is required")
        asset = asset_repository.update_asset(
            asset_id, changes, actor=session["username"], role=session.get("role"),
        )
        return (jsonify(asset), 200) if asset else (jsonify({"error": "Asset not found"}), 404)
    except ValueError as exc:
        return _asset_error(exc)


@app.route("/api/alerts/<alert_id>/notes", methods=["POST"])
@role_required("analyst")
def api_alert_note(alert_id):
    body = request.get_json(silent=True) or {}
    try:
        alert = add_analyst_note(alert_id, body.get("note"), session["username"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    append_audit_event(
        "NOTE_ADDED", session["username"], role=session.get("role"),
        target_type="incident", target_id=alert["incident_id"],
        details={"note_length": len(str(body.get("note", "")).strip())},
    )
    return jsonify(alert)


@app.route("/api/alerts/<alert_id>/feedback", methods=["POST"])
@role_required("analyst")
def api_alert_feedback(alert_id):
    if request.content_length and request.content_length > 8 * 1024:
        return jsonify({"error": "Feedback request exceeds 8 KiB"}), 413
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400
    unknown = set(body) - {"classification", "reason"}
    if unknown:
        return jsonify({"error": f"Unsupported feedback fields: {', '.join(sorted(unknown))}"}), 400
    try:
        feedback = alert_repository.create_detection_feedback(
            alert_id, body.get("classification"), body.get("reason", ""),
            session["username"], session.get("role"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if feedback is None:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(feedback), 201


@app.route("/api/alerts/<alert_id>/assignee", methods=["PATCH"])
@role_required("analyst")
def api_alert_assignee(alert_id):
    body = request.get_json(silent=True) or {}
    if "assigned_to" not in body:
        return jsonify({"error": "assigned_to is required"}), 400
    try:
        alert = update_assignee(alert_id, body["assigned_to"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    event = alert["timeline"][-1]
    append_audit_event(
        "ASSIGNMENT_CHANGED", session["username"], role=session.get("role"),
        target_type="incident", target_id=alert["incident_id"],
        details={"from": event.get("from_assignee"), "to": event.get("to_assignee")},
    )
    return jsonify(alert)


@app.route("/api/alerts/<alert_id>/response-actions", methods=["POST"])
@role_required("analyst")
def api_alert_response_action(alert_id):
    body = request.get_json(silent=True) or {}
    try:
        alert = request_response_action(alert_id, body.get("action_type"), body.get("target"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    action = alert["response_actions"][-1]
    audit_common = {
        "actor": session["username"], "role": session.get("role"),
        "target_type": "response_action", "target_id": action["action_id"],
    }
    append_audit_event(
        "RESPONSE_REQUESTED", **audit_common,
        details={"incident_id": alert["incident_id"], "action_type": action["action_type"]},
    )
    if action["status"] == "SIMULATED":
        append_audit_event(
            "RESPONSE_EXECUTED", **audit_common, outcome="SIMULATED",
            details={"incident_id": alert["incident_id"], "action_type": action["action_type"]},
        )
    return jsonify(alert), 201


@app.route("/api/alerts/<alert_id>/response-actions/<action_id>/approve", methods=["POST"])
@role_required("analyst")
def api_alert_response_action_approve(alert_id, action_id):
    try:
        alert = approve_response_action(alert_id, action_id, session["username"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    action = next(item for item in alert["response_actions"] if item["action_id"] == action_id)
    audit_common = {
        "actor": session["username"], "role": session.get("role"),
        "target_type": "response_action", "target_id": action_id,
    }
    approved = action.get("approved_by") == session["username"]
    append_audit_event(
        "RESPONSE_APPROVED", **audit_common, outcome="SUCCESS" if approved else "FAILED",
        details={"incident_id": alert["incident_id"], "action_type": action["action_type"]},
    )
    if approved:
        append_audit_event(
            "RESPONSE_EXECUTED", **audit_common, outcome=action["status"],
            details={"incident_id": alert["incident_id"], "action_type": action["action_type"]},
        )
    return jsonify(alert)


@app.route("/api/alerts/<alert_id>/response-actions/<action_id>/rollback", methods=["POST"])
@role_required("analyst")
def api_alert_response_action_rollback(alert_id, action_id):
    try:
        alert = rollback_response_action(alert_id, action_id, session["username"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    action = next(item for item in alert["response_actions"] if item["action_id"] == action_id)
    append_audit_event(
        "RESPONSE_ROLLED_BACK", session["username"], role=session.get("role"),
        target_type="response_action", target_id=action_id,
        details={"incident_id": alert["incident_id"], "action_type": action["action_type"]},
    )
    return jsonify(alert)

@app.route("/api/alerts/search")
def api_alerts_search():
    """
    Server-side filtering + pagination for Logs page.
    Query params:
      - page (default 1)
      - page_size (default 50, max 200)
      - severity (CRITICAL/HIGH/MEDIUM/LOW; legacy INFO is still readable)
      - q (free text: alert_name/description/raw_log)
      - ip (substring match)
      - mitre (substring match)
      - incident_status
      - human_review (true/false)
      - assigned_to (username or "me")
      - unassigned (true/false)
      - open_incidents (true/false)
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
    incident_status = (request.args.get("incident_status") or "").strip() or None
    ai_disposition = (request.args.get("ai_disposition") or "").strip() or None
    if not ai_disposition and (request.args.get("human_review") or "").lower() in {"1", "true", "yes"}:
        ai_disposition = "REQUIRES_HUMAN_REVIEW"
    assigned_to = (request.args.get("assigned_to") or "").strip() or None
    if assigned_to and assigned_to.lower() == "me":
        assigned_to = session.get("username")
    unassigned = (request.args.get("unassigned") or "").lower() in {"1", "true", "yes"}
    open_incidents = (request.args.get("open_incidents") or "").lower() in {"1", "true", "yes"}

    from_ts = _parse_ts_maybe(request.args.get("from"))
    to_ts = _parse_ts_maybe(request.args.get("to"))
    start = (page - 1) * page_size
    result = alert_repository.search_alerts(
        filters={
            "severity": severity,
            "q": q,
            "ip": ip,
            "mitre": mitre,
            "incident_status": incident_status,
            "ai_disposition": ai_disposition,
            "assigned_to": assigned_to,
            "unassigned": unassigned,
            "open_incidents": open_incidents,
            "from": from_ts.isoformat() if from_ts else None,
            "to": to_ts.isoformat() if to_ts else None,
        },
        limit=page_size,
        offset=start,
    )
    total = result["total"]

    return jsonify({
        "items": result["items"],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size
    })

@app.route("/api/graph")
def api_graph():
    """
    Context graph:
      - source_type -> IP
      - IP -> MITRE
      - IP -> Alert Name
      - Campaign node (if correlated_events exists) -> IP/Alert/MITRE
      - Campaign -> Event nodes (hash from correlated_events raw strings)
    """
    eff = _effective_settings()
    max_alerts = int(eff.get("GRAPH_MAX_ALERTS") or 500)
    include_sources = bool(eff.get("GRAPH_INCLUDE_SOURCES"))
    include_campaigns = bool(eff.get("GRAPH_INCLUDE_CAMPAIGNS"))

    # hard limits to keep graph readable
    MAX_EVENT_NODES_TOTAL = 100
    MAX_EVENTS_PER_CAMPAIGN = 5

    alerts = load_alerts(max_alerts)

    # Node counters
    ip_count = defaultdict(int)
    mitre_count = defaultdict(int)
    name_count = defaultdict(int)
    src_count = defaultdict(int)

    # Edge counters
    ip_to_mitre = defaultdict(int)
    ip_to_name = defaultdict(int)
    src_to_ip = defaultdict(int)

    # campaign_id -> dict
    campaigns = {}  # camp_id: {label, ip, mitre, name, events(list[str])}

    # event node store
    event_nodes = {}       # event_id -> {label, raw, count}
    camp_to_event = defaultdict(int)  # (camp_id, event_id) -> count

    def _safe_id(prefix: str, raw: str) -> str:
        h = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
        return f"{prefix}:{h}"

    def _short(s: str, n: int = 80) -> str:
        s = (s or "").strip()
        return s if len(s) <= n else (s[: n - 1] + "…")

    for a in alerts:
        ip = (a.get("ip_address") or "N/A").strip()
        mitre = (a.get("mitre_attck_id") or "N/A").strip()
        name = (a.get("alert_name") or "Unknown").strip()
        src = (a.get("source_type") or "HIDS_LOG").strip()

        if ip and ip != "N/A":
            ip_count[ip] += 1

            if mitre and mitre != "N/A":
                mitre_count[mitre] += 1
                ip_to_mitre[(ip, mitre)] += 1

            if name:
                name_count[name] += 1
                ip_to_name[(ip, name)] += 1

            if include_sources and src:
                src_count[src] += 1
                src_to_ip[(src, ip)] += 1

        if include_campaigns and a.get("correlated_events"):
            ev_list = a.get("correlated_events") or []
            # stable campaign id from key fields (best-effort)
            camp_raw = f"{a.get('timestamp','')}|{ip}|{name}|{mitre}|{len(ev_list)}"
            camp_id = _safe_id("camp", camp_raw)
            campaigns[camp_id] = {
                "label": f"Campaign: {name}",
                "ip": ip,
                "mitre": mitre,
                "name": name,
                "events": [str(x) for x in ev_list if str(x).strip()],
            }

    nodes = []
    edges = []

    def add_node(node_id: str, label: str, ntype: str, count: int, extra: dict | None = None):
        data = {"id": node_id, "label": label, "type": ntype, "count": int(count)}
        if extra:
            data.update(extra)
        nodes.append({"data": data})

    # --- Nodes ---
    if include_sources:
        for src, c in sorted(src_count.items(), key=lambda x: x[1], reverse=True)[:20]:
            add_node(f"src:{src}", src, "source", c)

    for ip, c in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:80]:
        add_node(f"ip:{ip}", ip, "ip", c)

    for mitre, c in sorted(mitre_count.items(), key=lambda x: x[1], reverse=True)[:80]:
        add_node(f"mitre:{mitre}", mitre, "mitre", c)

    for name, c in sorted(name_count.items(), key=lambda x: x[1], reverse=True)[:80]:
        add_node(f"alert:{name}", name, "alert", c)

    if include_campaigns:
        for camp_id, c in list(campaigns.items())[:50]:
            add_node(camp_id, c["label"], "campaign", max(1, len(c.get("events") or [])))

    # Build event nodes + edges (campaign -> event)
    if include_campaigns and campaigns:
        service_count = defaultdict(int)         # service -> count
        svc_to_event = defaultdict(int)          # (service_id, event_id) -> count

        def _kv(raw: str) -> dict:
            """
            Parse simple key=value tokens from raw strings if present.
            Example: "NETWORK_TRAFFIC src=1.2.3.4 proto=TCP flags=SYN dport=80"
            """
            out = {}
            for m in re.finditer(r"(\b[a-zA-Z_]+)=([^\s]+)", raw or ""):
                out[m.group(1).lower()] = m.group(2)
            return out

        def _classify_event(raw: str) -> tuple[str, str, str]:
            """
            Returns: (service, event_type, label)
            service: ssh/web/sudo/auth/network/honeypot/other
            event_type: more specific subtype for styling
            label: short readable label (tooltip shows full raw)
            """
            s = (raw or "").strip()
            sl = s.lower()

            # Honeypot / network sensor raw logs often have prefixes
            if "honeypot" in sl:
                return ("honeypot", "honeypot_conn", "HONEYPOT connection")

            if "network_traffic" in sl or "proto=tcp" in sl or "flags=syn" in sl or "arp" in sl:
                kv = _kv(s)
                if "arp" in sl:
                    return ("network", "net_arp", f"ARP: {kv.get('psrc','?')} → {kv.get('hwsrc','?')}")
                if "syn" in sl:
                    return ("network", "net_syn", f"SYN scan: src={kv.get('src','?')} dport={kv.get('dport','?')}")
                return ("network", "net", "Network event")

            # SSH / auth.log patterns
            if "sshd" in sl or re.search(r"\bssh\b", sl):
                m = re.search(r"failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)", sl)
                if m:
                    return ("ssh", "ssh_failed", f"SSH failed: {m.group('user')} @ {m.group('ip')}")
                m = re.search(r"accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)", sl)
                if m:
                    return ("ssh", "ssh_success", f"SSH accepted: {m.group('user')} @ {m.group('ip')}")
                if "invalid user" in sl:
                    return ("ssh", "ssh_invalid_user", "SSH invalid user")
                return ("ssh", "ssh", "SSH event")

            # Web / nginx / http
            if "nginx" in sl or "http" in sl or "get " in sl or "post " in sl:
                # common access log: "GET /path HTTP/1.1" 404
                mm = re.search(r"\b(get|post|put|delete|head|options)\b\s+(?P<path>/\S*)", sl)
                path = mm.group("path") if mm else "/"
                if " 404 " in f" {sl} " or re.search(r"\b404\b", sl):
                    return ("web", "web_404", f"HTTP 404: {path}")
                if re.search(r"\b5\d\d\b", sl):
                    return ("web", "web_5xx", f"HTTP 5xx: {path}")
                return ("web", "web", f"HTTP: {path}")

            # sudo
            if "sudo" in sl:
                # sudo:  user : TTY=... ; COMMAND=/bin/...
                mu = re.search(r"sudo:\s*(?P<user>\w+)\s*:", sl)
                user = mu.group("user") if mu else "user"
                return ("sudo", "sudo", f"Sudo: {user}")

            # generic auth/pam
            if "pam_unix" in sl or "authentication failure" in sl:
                return ("auth", "auth_fail", "Auth failure (PAM)")

            return ("other", "other", "Event")

        # global cap
        total_added = 0
        for camp_id, c in list(campaigns.items())[:50]:
            evs = (c.get("events") or [])[:MAX_EVENTS_PER_CAMPAIGN]
            for raw in evs:
                if total_added >= MAX_EVENT_NODES_TOTAL:
                    break

                raw = str(raw).strip()
                if not raw:
                    continue

                svc, event_type, label = _classify_event(raw)
                service_id = f"svc:{svc}"

                event_id = _safe_id("event", raw)
                if event_id not in event_nodes:
                    event_nodes[event_id] = {
                        "raw": raw,
                        "label": label,          # short label
                        "count": 0,
                        "service": svc,
                        "event_type": event_type,
                        "service_id": service_id,
                    }
                    total_added += 1

                event_nodes[event_id]["count"] += 1
                service_count[svc] += 1

                camp_to_event[(camp_id, event_id)] += 1
                svc_to_event[(service_id, event_id)] += 1

            if total_added >= MAX_EVENT_NODES_TOTAL:
                break

        # Add service nodes
        # (small number of services => readable grouping)
        for svc, cnt in sorted(service_count.items(), key=lambda x: x[1], reverse=True):
            add_node(
                f"svc:{svc}",
                svc.upper(),
                "service",
                cnt,
                extra={"service": svc},
            )

        # Add event nodes (with service + event_type for styling)
        for event_id, meta in event_nodes.items():
            add_node(
                event_id,
                meta["label"],
                "event",
                meta["count"],
                extra={
                    "raw": meta["raw"],
                    "service": meta["service"],
                    "event_type": meta["event_type"],
                    "service_id": meta["service_id"],
                },
            )

        # Add service -> event edges (hidden by default on UI, revealed with campaign)
        for (service_id, event_id), cnt in sorted(svc_to_event.items(), key=lambda x: x[1], reverse=True)[:600]:
            edges.append({
                "data": {
                    "id": f"e:svcev:{service_id}->{event_id}",
                    "source": service_id,
                    "target": event_id,
                    "label": "" if cnt <= 1 else str(cnt),
                    "count": int(cnt),
                    "etype": "svc_event",
                    "event_type": event_nodes.get(event_id, {}).get("event_type", "other"),
                    "service": event_nodes.get(event_id, {}).get("service", "other"),
                }
            })

    # campaign -> event edges
    for (camp_id, event_id), c in sorted(camp_to_event.items(), key=lambda x: x[1], reverse=True)[:400]:
        meta = event_nodes.get(event_id, {})
        edges.append({
            "data": {
                "id": f"e:campev:{camp_id}->{event_id}",
                "source": camp_id,
                "target": event_id,
                "label": "" if c <= 1 else str(c),
                "count": int(c),
                "etype": "camp_event",
                "event_type": meta.get("event_type", "other"),
                "service": meta.get("service", "other"),
            }
        })

    return jsonify({"nodes": nodes, "edges": edges})

@app.route("/graph")
def graph_page():
    return render_template("graph.html", page="graph")

if __name__ == "__main__":
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=False)
