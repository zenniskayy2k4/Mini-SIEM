"""
ai_analyst.py - Provider-neutral LLM Analyst (Layer 3)

Responsibilities:
  - Async triage of HIGH/CRITICAL alerts through an AIProvider
  - False-positive assessment with confidence score
  - MITRE tactic/technique mapping suggestion
  - Automated playbook generation tailored to the alert type
  - Alert deduplication within a TTL window

Setup:
  export AI_PROVIDER="ollama_cloud"
  export OLLAMA_API_KEY="..."
  export OLLAMA_BASE_URL="https://ollama.com/api"
  export OLLAMA_MODEL="gemma4:cloud"

The analyst runs in a background thread pool so it does not block the
detection pipeline. Results are written back into the alert dictionary.
"""

import json
import logging
import re
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from src.ai_provider import AIProvider


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """You are an expert SOC analyst and threat intelligence specialist.
You receive a structured SIEM alert and must return a JSON analysis.

Return ONLY valid JSON. No markdown, no explanation outside the JSON.

Use only evidence explicitly present in the alert. Separate observed facts from
analyst inference, say when evidence is insufficient, and never claim successful
authentication, compromise, or attack progression unless the alert proves it.

Required JSON schema:
{
  "is_false_positive": bool,
  "fp_confidence": int,          // 0-100: how confident FP assessment is
  "threat_confidence": int,      // 0-100: confidence this is a real threat
  "mitre_tactic": string,        // e.g. "Initial Access", "Credential Access"
  "mitre_technique": string,     // e.g. "T1110.001 - Password Guessing"
  "threat_summary": string,      // 1-2 sentences, plain English
  "observed_facts": [string],    // facts directly present in the alert
  "analyst_inferences": [string],// cautious conclusions, empty if unsupported
  "recommended_playbook": [      // ordered list of response steps
    "Step 1: ...",
    "Step 2: ...",
    ...
  ],
  "ioc_tags": [string],          // extracted IOCs (IPs, hashes, domains, etc.)
  "escalate_to_human": bool      // true if this needs immediate human review
}"""

_USER_TEMPLATE = """Analyse this SIEM alert:

Alert Name    : {alert_name}
Severity      : {severity}
MITRE ID      : {mitre_attck_id}
Source IP     : {ip_address}
Source Type   : {source_type}
Description   : {description}
Raw Log       : {raw_log}
Timestamp     : {timestamp}
Event Count   : {event_count}
Window Seconds: {window_seconds}
First Seen    : {first_seen}
Last Seen     : {last_seen}
Target Users  : {target_users}
Threat Intel  : {threat_intel}
"""


# ---------------------------------------------------------------------------
# Simple TTL cache to avoid re-analysing identical alert types
# ---------------------------------------------------------------------------
class _TTLCache:
    """Thread-safe LRU cache with TTL expiry."""

    def __init__(self, maxsize: int = 200, ttl_seconds: int = 120):
        self._cache: OrderedDict[str, tuple[dict, float]] = OrderedDict()
        self._maxsize    = maxsize
        self._ttl        = ttl_seconds
        self._lock       = threading.Lock()

    def get(self, key: str) -> dict | None:
        with self._lock:
            item = self._cache.get(key)
            if item is None:
                return None
            value, exp = item
            if time.monotonic() > exp:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return value

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (value, time.monotonic() + self._ttl)
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)


# ---------------------------------------------------------------------------
# Rate limiter (token-bucket)
# ---------------------------------------------------------------------------
class _RateLimiter:
    """Allow at most `rate` calls per `period` seconds."""

    def __init__(self, rate: int = 10, period: float = 60.0):
        self._rate    = rate
        self._period  = period
        self._tokens  = rate
        self._last    = time.monotonic()
        self._lock    = threading.Lock()

    def acquire(self) -> bool:
        """Return True if a token is available (non-blocking)."""
        with self._lock:
            now    = time.monotonic()
            elapsed = now - self._last
            refill  = elapsed * (self._rate / self._period)
            self._tokens = min(self._rate, self._tokens + refill)
            self._last   = now
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


# ---------------------------------------------------------------------------
# AIAnalyst
# ---------------------------------------------------------------------------
class AIAnalyst:
    """
    Enriches SIEM alerts through an injected provider in a background thread pool.

    Usage:
        analyst = AIAnalyst(provider)
        detector = ThreatDetector(
            signatures,
            ai_analyst=analyst,
        )
    """

    def __init__(
        self,
        provider: AIProvider,
        cache_ttl: int = 120,
        rate_per_min: int = 10,
    ):
        if not isinstance(provider, AIProvider):
            raise TypeError("provider must implement AIProvider")
        if not isinstance(provider.name, str) or not provider.name.strip():
            raise ValueError("provider name must not be empty")
        if not isinstance(provider.model, str) or not provider.model.strip():
            raise ValueError("provider model must not be empty")
        self._provider_client = provider
        self._provider = provider.name.strip()
        self._model = provider.model.strip()
        self._enabled = bool(provider.available())

        if not self._enabled:
            logger.warning(
                "[AIAnalyst] AI provider %s is not configured; Layer 3 analysis disabled.",
                self._provider,
            )
        else:
            logger.info(
                "[AIAnalyst] AI provider %s enabled with model=%s",
                self._provider, self._model,
            )

        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="ollama_analyst",
        )
        self._single_flight = threading.Lock()
        self._available = None
        self._last_success_at = None
        self._last_failure_at = None

        self._cache = _TTLCache(
            maxsize=200,
            ttl_seconds=cache_ttl,
        )

        self._limiter = _RateLimiter(
            rate=rate_per_min,
            period=60.0,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def enrich_async(self, alert: dict, on_complete=None) -> None:
        """
        Submit alert for analysis in a background thread.
        The result is written back into `alert` dict in-place
        and also logged. Never raises.
        """
        if not self._enabled:
            return
        if not self._single_flight.acquire(blocking=False):
            self._mark_skipped(alert, "busy")
            logger.info("[AIAnalyst] Busy; skipped %s", alert.get("alert_name"))
            if on_complete:
                try:
                    on_complete(alert)
                except Exception as exc:
                    logger.warning(f"[AIAnalyst] Completion callback failed: {exc}")
            return
        future = self._executor.submit(self._safe_enrich, alert)
        future.add_done_callback(self._completion(on_complete))

    def enrich_sync(self, alert: dict) -> dict:
        """
        Blocking version — useful for testing or forced triage.
        Returns the enriched alert dict.
        """
        if not self._enabled:
            return alert
        with self._single_flight:
            return self._safe_enrich(alert)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)

    def health_status(self) -> dict:
        return {
            "enabled": self._enabled,
            "provider": self._provider,
            "model": self._model,
            "available": self._available,
            "last_successful_enrichment": self._last_success_at,
            "last_failure": self._last_failure_at,
            "busy": self._single_flight.locked(),
            "backlog": 0,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _completion(self, on_complete):
        def run(done):
            try:
                result = done.result()
                if on_complete:
                    on_complete(result)
            except Exception as exc:
                logger.warning(f"[AIAnalyst] Completion callback failed: {exc}")
            finally:
                self._single_flight.release()

        return run

    def _mark_skipped(self, alert, reason):
        alert["ai_analysis"] = {
            "skipped": reason,
            "provider": self._provider,
            "model": self._model,
        }

    def _cache_key(self, alert: dict) -> str:
        """Deduplicate similar alerts without merging different sources."""
        return "|".join(
            [
                str(alert.get("alert_name", "")),
                str(alert.get("severity", "")),
                str(alert.get("source_type", "")),
                str(alert.get("ip_address", "")),
                str(alert.get("mitre_attck_id", "")),
                str(alert.get("event_count", "")),
                str(alert.get("last_seen", "")),
            ]
        )

    @staticmethod
    def _threat_intel_summary(alert: dict) -> str:
        entry = (alert.get("threat_intel") or {}).get("abuseipdb") or {}
        allowed = (
            "ioc", "status", "abuse_confidence", "total_reports",
            "last_reported_at", "isp", "domain", "usage_type",
        )
        return json.dumps(
            {key: entry.get(key) for key in allowed if key in entry},
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _safe_enrich(self, alert: dict) -> dict:
        try:
            result = self._enrich(alert)
            analysis = result.get("ai_analysis") or {}
            if analysis.get("analysed_at") and not analysis.get("cached"):
                self._available = True
                self._last_success_at = analysis["analysed_at"]
            return result
        except Exception as exc:
            self._available = False
            self._last_failure_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            logger.warning(f"[AIAnalyst] Enrichment failed: {exc}")
            alert["ai_analyst_error"] = str(exc)
            alert["ai_analysis"] = {
                "error": str(exc),
                "provider": self._provider,
                "model": self._model,
            }
            return alert

    def _enrich(self, alert: dict) -> dict:
        key = self._cache_key(alert)

        # Return cached result if available (attaches to current alert)
        cached = self._cache.get(key)
        if cached:
            cached_analysis = dict(cached)
            cached_analysis["cached"] = True
            self._apply_ai_recommendation(alert, cached_analysis)
            return alert

        # Rate-limit check
        if not self._limiter.acquire():
            logger.debug("[AIAnalyst] Rate limit hit, skipping analysis.")
            self._mark_skipped(alert, "rate_limited")
            return alert

        # Build prompt
        user_msg = _USER_TEMPLATE.format(
            alert_name    = alert.get("alert_name",    "Unknown"),
            severity      = alert.get("severity",      "Unknown"),
            mitre_attck_id= alert.get("mitre_attck_id","Unknown"),
            ip_address    = alert.get("ip_address",    "N/A"),
            source_type   = alert.get("source_type",   "UNKNOWN"),
            description   = alert.get("description",   ""),
            raw_log       = (alert.get("raw_log", "") or "")[:300],  # trim long logs
            timestamp     = alert.get("timestamp",     ""),
            event_count   = alert.get("event_count"),
            window_seconds= alert.get("window_seconds"),
            first_seen    = alert.get("first_seen"),
            last_seen     = alert.get("last_seen"),
            target_users  = json.dumps(alert.get("target_users"), ensure_ascii=False),
            threat_intel  = self._threat_intel_summary(alert),
        )

        raw_text = self._provider_client.analyze([
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ], "json")

        # Parse JSON response
        analysis = self._parse_response(raw_text)
        analysis.setdefault("observed_facts", [])
        analysis.setdefault("analyst_inferences", [])
        analysis["provider"] = self._provider
        analysis["model"] = self._model
        analysis["analysed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        analysis["cached"]      = False

        # Cache + write back
        self._cache.set(key, analysis)
        self._apply_ai_recommendation(alert, analysis)

        logger.info(
            f"[AIAnalyst] {alert.get('alert_name')} → "
            f"FP={analysis.get('is_false_positive')} "
            f"(fp_conf={analysis.get('fp_confidence')}%) "
            f"threat_conf={analysis.get('threat_confidence')}%"
        )
        return alert

    @staticmethod
    def _apply_ai_recommendation(alert: dict, analysis: dict) -> None:
        alert["ai_analysis"] = analysis
        alert["ai_recommended_severity"] = alert.get("severity", "UNKNOWN")

        if analysis.get("escalate_to_human"):
            alert["ai_recommended_severity"] = "CRITICAL"
            alert["ai_disposition"] = "REQUIRES_HUMAN_REVIEW"

        if analysis.get("is_false_positive") and analysis.get("fp_confidence", 0) >= 80:
            alert["ai_recommended_severity"] = "LOW"
            alert["ai_disposition"] = "FALSE_POSITIVE_SUSPECTED"

    @staticmethod
    def _parse_response(text: str) -> dict:
        """Extract JSON from LLM response, tolerating minor formatting issues."""
        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Fallback: try to find a JSON object anywhere in the text
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
        return {"parse_error": "Could not decode LLM response", "raw": text[:200]}
