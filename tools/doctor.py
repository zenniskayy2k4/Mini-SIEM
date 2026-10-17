"""Mini-SIEM environment doctor — read-only operator preflight checks."""

import json
import os
import sqlite3
import sys
from pathlib import Path

from config import config
from config.secrets import SECRET_NAMES, read_secret
from tools.validate_config import load_environment, validate as validate_config


def _check_directories() -> dict:
    required = [
        ("BASE_DIR", config.BASE_DIR),
        ("RULES_DIR", config.RULES_DIR),
        ("SIGMA_RULES_DIR", config.SIGMA_RULES_DIR),
    ]
    results = []
    for name, path in required:
        p = Path(path)
        exists = p.exists() and p.is_dir()
        results.append({
            "name": name,
            "path": str(p),
            "exists": exists,
            "readable": p.exists() and os.access(p, os.R_OK) if exists else False,
            "status": "ok" if exists else "missing",
        })
    return results


def _check_writable_paths() -> dict:
    writable = [
        ("DATA_DIR", os.path.dirname(config.SQLITE_ALERT_DB)),
        ("SQLITE_BACKUP_DIR", config.SQLITE_BACKUP_DIR),
        ("ALERT_ARCHIVE_DIR", config.ALERT_ARCHIVE_DIR),
    ]
    results = []
    for name, path in writable:
        p = Path(path)
        writable = p.exists() and os.access(p, os.W_OK)
        results.append({
            "name": name,
            "path": str(p),
            "writable": writable,
            "status": "ok" if writable else "not_writable",
        })
    return results


def _check_database() -> dict:
    db_path = Path(config.SQLITE_ALERT_DB)
    if not db_path.is_file():
        return {"status": "missing", "path": str(db_path), "integrity": None}

    try:
        uri = f"file:{db_path}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as conn:
            check = conn.execute("PRAGMA integrity_check(1)").fetchone()[0]
        return {
            "status": "ok" if check == "ok" else "corrupt",
            "path": str(db_path),
            "integrity": check,
        }
    except (OSError, sqlite3.Error) as exc:
        return {
            "status": "error",
            "path": str(db_path),
            "integrity": None,
            "error": type(exc).__name__,
        }


def _check_dashboard_users() -> dict:
    users_path = Path(config.DASHBOARD_USERS_FILE)
    if not users_path.is_file():
        return {"status": "missing", "path": str(users_path), "admins": []}

    try:
        with users_path.open(encoding="utf-8") as f:
            users = json.load(f)
        admins = [
            username for username, data in users.items()
            if isinstance(data, dict) and data.get("role") == "admin"
        ]
        return {
            "status": "ok",
            "path": str(users_path),
            "admins": admins,
            "total_users": len(users),
        }
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "error",
            "path": str(users_path),
            "admins": [],
            "error": type(exc).__name__,
        }


def _check_config() -> dict:
    try:
        values = load_environment()
        issues = validate_config(values)
        errors = [i for i in issues if i["level"] == "ERROR"]
        warnings = [i for i in issues if i["level"] == "WARNING"]
        return {
            "status": "ok" if not errors else "error",
            "errors": errors,
            "warnings": warnings,
            "total_errors": len(errors),
            "total_warnings": len(warnings),
        }
    except (OSError, ValueError) as exc:
        return {
            "status": "error",
            "error": str(exc),
            "errors": [],
            "warnings": [],
        }


def _check_integrations() -> dict:
    results = []

    if config.CASE_EXPORT_ENABLED:
        provider = config.CASE_EXPORT_PROVIDER.lower()
        if provider == "thehive":
            configured = bool(config.THEHIVE_URL and config.THEHIVE_API_KEY)
            results.append({
                "name": "TheHive",
                "configured": configured,
                "status": "configured" if configured else "missing_credentials",
                "url": bool(config.THEHIVE_URL),
            })
        elif provider == "jira":
            configured = bool(
                config.JIRA_URL and config.JIRA_USER_EMAIL and config.JIRA_API_TOKEN
                and config.JIRA_PROJECT_KEY
            )
            results.append({
                "name": "Jira",
                "configured": configured,
                "status": "configured" if configured else "missing_credentials",
                "url": bool(config.JIRA_URL),
            })
    else:
        results.append({"name": "Case Export", "configured": False, "status": "disabled"})

    ti_providers = []
    if config.ABUSEIPDB_API_KEY:
        ti_providers.append("AbuseIPDB")
    if config.VIRUSTOTAL_API_KEY:
        ti_providers.append("VirusTotal")
    if config.STIX_BUNDLE_FILE:
        ti_providers.append("STIX")
    if config.TAXII_COLLECTION_URL:
        ti_providers.append("TAXII")

    results.append({
        "name": "Threat Intelligence",
        "configured": bool(ti_providers),
        "status": "configured" if ti_providers else "none_configured",
        "providers": ti_providers,
    })

    return results


def _check_collector() -> dict:
    collector_configured = bool(config.WINDOWS_COLLECTOR_SECRET)
    return {
        "collector_configured": collector_configured,
        "status": "configured" if collector_configured else "not_configured",
        "stale_threshold_seconds": config.WINDOWS_COLLECTOR_STALE_SECONDS,
    }


def _check_ai_readiness() -> dict:
    provider = config.AI_PROVIDER.lower()
    fallback = config.AI_FALLBACK_PROVIDER.lower()
    ollama_key = bool(config.OLLAMA_API_KEY)

    results = []

    primary_result = {
        "provider": provider,
        "key_configured": ollama_key if provider == "ollama_cloud" else None,
        "url": config.OLLAMA_BASE_URL if provider == "ollama_cloud" else None,
    }

    if provider == "ollama_cloud":
        if not ollama_key:
            primary_result["status"] = "missing_key"
            primary_result["ready"] = False
        else:
            primary_result["status"] = "configured"
            primary_result["ready"] = True
    elif provider == "ollama_local":
        primary_result["status"] = "configured"
        primary_result["ready"] = True
    else:
        primary_result["status"] = "unknown"
        primary_result["ready"] = False

    results.append(primary_result)

    if fallback:
        fallback_result = {
            "provider": fallback,
            "fallback": True,
            "key_configured": ollama_key if fallback == "ollama_cloud" else None,
        }
        if fallback == "ollama_cloud" and not ollama_key:
            fallback_result["status"] = "missing_key"
            fallback_result["ready"] = False
        else:
            fallback_result["status"] = "configured"
            fallback_result["ready"] = True
        results.append(fallback_result)

    return results


def run_doctor() -> dict:
    checks = {
        "directories": _check_directories(),
        "writable_paths": _check_writable_paths(),
        "database": _check_database(),
        "dashboard_users": _check_dashboard_users(),
        "config": _check_config(),
        "integrations": _check_integrations(),
        "collector": _check_collector(),
        "ai_readiness": _check_ai_readiness(),
    }

    critical_statuses = {"missing", "not_writable", "error", "corrupt"}
    has_critical = False

    for check_name, result in checks.items():
        if check_name == "database" and result.get("status") in critical_statuses:
            has_critical = True
        elif check_name == "dashboard_users":
            if result.get("status") in critical_statuses:
                has_critical = True
            elif result.get("status") == "ok" and not result.get("admins"):
                has_critical = True
                result["status"] = "no_admin"
        elif check_name == "config" and result.get("total_errors", 0) > 0:
            has_critical = True
        elif check_name == "writable_paths":
            for path in result:
                if path.get("status") in critical_statuses:
                    has_critical = True
                    break

    return {
        "status": "fail" if has_critical else "pass",
        "checks": checks,
    }


def main():
    result = run_doctor()
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if result["status"] == "pass":
        print("\nEnvironment doctor: PASS")
        return 0
    else:
        print("\nEnvironment doctor: FAIL")
        return 1


if __name__ == "__main__":
    sys.exit(main())
