import math


DEFAULT_WEIGHTS = {
    "detection_severity": 40,
    "asset_criticality": 20,
    "threat_confidence": 15,
    "ti_reputation": 15,
    "correlation_count": 5,
    "human_review": 5,
}
LEVEL_SIGNALS = {"LOW": 0.1, "MEDIUM": 0.35, "HIGH": 0.7, "CRITICAL": 1.0}


def _number(value, default=0.0):
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError):
        return default


def _percent(value):
    return max(0.0, min(100.0, _number(value)))


def _ti_reputation(alert):
    intel = alert.get("threat_intel") if isinstance(alert.get("threat_intel"), dict) else {}
    candidates = []

    abuseipdb = intel.get("abuseipdb") or {}
    if abuseipdb.get("status") == "ok":
        candidates.append((_percent(abuseipdb.get("abuse_confidence")), "abuseipdb"))

    virustotal = intel.get("virustotal") or {}
    if virustotal.get("status") == "ok":
        malicious = max(0.0, _number(virustotal.get("malicious")))
        suspicious = max(0.0, _number(virustotal.get("suspicious")))
        total = sum(max(0.0, _number(virustotal.get(field))) for field in (
            "malicious", "suspicious", "harmless", "undetected",
        ))
        detection_ratio = 100 * (malicious + suspicious * 0.5) / total if total else 0
        negative_reputation = max(0.0, -_number(virustotal.get("reputation")))
        candidates.append((min(100.0, max(detection_ratio, negative_reputation)), "virustotal"))

    stix = intel.get("stix") or {}
    if stix.get("status") == "ok" and _number(stix.get("match_count")) > 0:
        confidence = 50 if stix.get("confidence") is None else _percent(stix["confidence"])
        candidates.append((confidence, "stix"))

    return max(candidates, default=(0.0, None), key=lambda item: item[0])


def score_alert_risk(alert: dict, asset=None, weights=None) -> dict:
    """Calculate a deterministic 0-100 score without accepting an LLM-provided score."""
    weights = DEFAULT_WEIGHTS if weights is None else weights
    factors = []

    def add(factor, value, signal, **details):
        points = int(round(max(0.0, _number(weights.get(factor))) * max(0.0, min(1.0, signal))))
        if points:
            factors.append({"factor": factor, "value": value, "points": points, **details})

    severity = str(alert.get("severity") or "").upper()
    add("detection_severity", severity, LEVEL_SIGNALS.get(severity, 0))

    criticality = str((asset or {}).get("criticality") or "").upper()
    add("asset_criticality", criticality, LEVEL_SIGNALS.get(criticality, 0))

    analysis = alert.get("ai_analysis") if isinstance(alert.get("ai_analysis"), dict) else {}
    confidence = _percent(analysis.get("threat_confidence"))
    add("threat_confidence", round(confidence), confidence / 100)

    reputation, provider = _ti_reputation(alert)
    add("ti_reputation", round(reputation), reputation / 100, provider=provider)

    event_count = max(1, int(_number(alert.get("event_count"), 1)))
    add("correlation_count", event_count, min(1.0, (event_count - 1) / 9))

    human_review = bool(
        analysis.get("escalate_to_human")
        or alert.get("ai_disposition") == "REQUIRES_HUMAN_REVIEW"
    )
    add("human_review", human_review, 1.0 if human_review else 0.0)

    score = min(100, sum(factor["points"] for factor in factors))
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    alert.update({"risk_score": score, "risk_level": level, "risk_factors": factors})
    return alert
