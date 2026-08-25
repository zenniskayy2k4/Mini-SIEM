from collections import Counter
import json


SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO")
INCIDENT_STATUSES = ("NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE")
TI_PROVIDERS = ("ipwhois", "abuseipdb", "virustotal", "stix")


def _label(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _family(lines, name, description, samples):
    lines.extend((f"# HELP {name} {description}", f"# TYPE {name} gauge"))
    for labels, value in samples:
        suffix = "{" + ",".join(f'{key}="{_label(item)}"' for key, item in labels.items()) + "}" if labels else ""
        lines.append(f"{name}{suffix} {value}")


def _notification_counts(path):
    counts = Counter()
    try:
        with open(path, encoding="utf-8") as file:
            for line in file:
                try:
                    status = json.loads(line).get("status")
                except (json.JSONDecodeError, TypeError):
                    continue
                if status in {"SENT", "FAILED"}:
                    counts["success" if status == "SENT" else "failure"] += 1
    except OSError:
        pass
    return counts


def render_prometheus_metrics(
    alerts, rules, system_status, notification_log, ingestion_failures=None,
):
    # ponytail: one retained-alert scan fits the lab; use SQL aggregates if scrape latency grows.
    severities = Counter()
    incidents = Counter()
    ai = Counter()
    ti = Counter()
    simulations = 0
    for alert in alerts:
        severity = str(alert.get("severity") or "").upper()
        if severity in SEVERITIES:
            severities[severity] += 1
        incident_status = str(alert.get("incident_status") or "").upper()
        if alert.get("incident_id") and incident_status in INCIDENT_STATUSES:
            incidents[incident_status] += 1

        analysis = alert.get("ai_analysis") if isinstance(alert.get("ai_analysis"), dict) else {}
        if analysis.get("analysed_at"):
            ai["success"] += 1
        elif analysis.get("error") or alert.get("ai_analyst_error"):
            ai["failure"] += 1

        intel = alert.get("threat_intel") if isinstance(alert.get("threat_intel"), dict) else {}
        for provider in TI_PROVIDERS:
            entry = intel.get(provider) if isinstance(intel.get(provider), dict) else {}
            status = entry.get("status")
            if status in {"ok", "not_found"}:
                ti[(provider, "success")] += 1
            elif status in {"error", "timeout"}:
                ti[(provider, "failure")] += 1

        simulations += sum(
            action.get("mode") == "simulation"
            for action in alert.get("response_actions") or []
            if isinstance(action, dict)
        )

    notifications = _notification_counts(notification_log)
    queue = system_status.get("queue") or {}
    heartbeat_age = (system_status.get("agent") or {}).get("age_seconds")
    lines = []
    _family(lines, "mini_siem_metrics_up", "Whether metric collection succeeded.", [({}, 1)])
    _family(lines, "mini_siem_alerts", "Retained alerts by severity.", [
        ({"severity": severity}, severities[severity]) for severity in SEVERITIES
    ])
    _family(lines, "mini_siem_incidents", "Current incidents by lifecycle status.", [
        ({"status": status}, incidents[status]) for status in INCIDENT_STATUSES
    ])
    _family(lines, "mini_siem_detection_hits", "Retained alert hits by loaded rule.", [
        ({"rule_id": rule["rule_id"], "source": rule["rule_source"]}, int(rule["hit_count"]))
        for rule in rules
    ])
    _family(lines, "mini_siem_ai_enrichments", "Retained AI enrichment outcomes.", [
        ({"result": result}, ai[result]) for result in ("success", "failure")
    ])
    _family(lines, "mini_siem_ti_lookups", "Retained threat-intelligence lookup outcomes.", [
        ({"provider": provider, "result": result}, ti[(provider, result)])
        for provider in TI_PROVIDERS for result in ("success", "failure")
    ])
    _family(lines, "mini_siem_notifications", "Recorded webhook notification outcomes.", [
        ({"result": result}, notifications[result]) for result in ("success", "failure")
    ])
    _family(lines, "mini_siem_response_simulations", "Retained simulation-mode response actions.", [
        ({}, simulations)
    ])
    _family(lines, "mini_siem_agent_heartbeat_age_seconds", "Age of the latest agent heartbeat.", [
        ({}, "NaN" if heartbeat_age is None else max(0, float(heartbeat_age)))
    ])
    _family(lines, "mini_siem_ai_worker_busy", "Whether the shared AI worker is busy.", [
        ({}, int(bool(queue.get("busy"))))
    ])
    _family(lines, "mini_siem_ai_queue_backlog", "Current AI queue backlog.", [
        ({}, max(0, int(queue.get("backlog") or 0)))
    ])
    failures = ingestion_failures or {}
    _family(lines, "mini_siem_ingestion_failures", "Retained ingestion failures by bounded type.", [
        ({"type": failure_type}, max(0, int(failures.get(failure_type) or 0)))
        for failure_type in ("parser", "schema", "unsupported")
    ])
    return "\n".join(lines) + "\n"


def metrics_unavailable():
    return "# HELP mini_siem_metrics_up Whether metric collection succeeded.\n# TYPE mini_siem_metrics_up gauge\nmini_siem_metrics_up 0\n"
