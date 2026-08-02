"""
ai_analyst.py - Ollama Cloud LLM Analyst (Layer 3)

Responsibilities:
  - Async triage of HIGH/CRITICAL alerts via Ollama Cloud API
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

import os
import json
import logging
import re
import threading
import time
import requests
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """You are an expert SOC analyst and threat intelligence specialist.
You receive a structured SIEM alert and must return a JSON analysis.

Return ONLY valid JSON. No markdown, no explanation outside the JSON.

Required JSON schema:
{
  "is_false_positive": bool,
  "fp_confidence": int,          // 0-100: how confident FP assessment is
  "threat_confidence": int,      // 0-100: confidence this is a real threat
  "mitre_tactic": string,        // e.g. "Initial Access", "Credential Access"
  "mitre_technique": string,     // e.g. "T1110.001 - Password Guessing"
  "threat_summary": string,      // 1-2 sentences, plain English
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
    Enriches SIEM alerts with Ollama Cloud analysis
    in a background thread pool.

    Usage:
        analyst = AIAnalyst()
        detector = ThreatDetector(
            signatures,
            ai_analyst=analyst,
        )
    """

    MAX_TOKENS  = 800
    TEMPERATURE = 0.1   # near-deterministic for structured analysis

    def __init__(
        self,
        api_key: str | None = None,
        max_workers: int = 3,
        cache_ttl: int = 120,
        rate_per_min: int = 10,
    ):
        self._provider = os.environ.get(
            "AI_PROVIDER",
            "ollama_cloud",
        ).strip().lower()

        self._api_key = (
            api_key
            or os.environ.get("OLLAMA_API_KEY", "")
        ).strip()

        self._base_url = os.environ.get(
            "OLLAMA_BASE_URL",
            "https://ollama.com/api",
        ).rstrip("/")

        self._model = os.environ.get(
            "OLLAMA_MODEL",
            "gemma4:cloud",
        ).strip()

        self._enabled = (
            self._provider == "ollama_cloud"
            and bool(self._api_key)
        )

        if not self._enabled:
            logger.warning(
                "[AIAnalyst] Ollama Cloud configuration missing. "
                "Layer 3 analysis disabled. "
                "Set AI_PROVIDER=ollama_cloud and OLLAMA_API_KEY."
            )
        else:
            logger.info(
                "[AIAnalyst] Ollama Cloud enabled "
                f"with model={self._model}"
            )

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="ollama_analyst",
        )

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
    def enrich_async(self, alert: dict) -> None:
        """
        Submit alert for analysis in a background thread.
        The result is written back into `alert` dict in-place
        and also logged. Never raises.
        """
        if not self._enabled:
            return
        self._executor.submit(self._safe_enrich, alert)

    def enrich_sync(self, alert: dict) -> dict:
        """
        Blocking version — useful for testing or forced triage.
        Returns the enriched alert dict.
        """
        if not self._enabled:
            return alert
        return self._safe_enrich(alert)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _cache_key(self, alert: dict) -> str:
        """Deduplicate similar alerts without merging different sources."""
        return "|".join(
            [
                str(alert.get("alert_name", "")),
                str(alert.get("severity", "")),
                str(alert.get("source_type", "")),
                str(alert.get("ip_address", "")),
                str(alert.get("mitre_attck_id", "")),
            ]
        )

    def _safe_enrich(self, alert: dict) -> dict:
        try:
            return self._enrich(alert)
        except Exception as exc:
            logger.warning(f"[AIAnalyst] Enrichment failed: {exc}")
            alert["ai_analyst_error"] = str(exc)
            return alert

    def _enrich(self, alert: dict) -> dict:
        key = self._cache_key(alert)

        # Return cached result if available (attaches to current alert)
        cached = self._cache.get(key)
        if cached:
            cached_analysis = dict(cached)
            cached_analysis["cached"] = True
            alert["ai_analysis"] = cached_analysis
            return alert

        # Rate-limit check
        if not self._limiter.acquire():
            logger.debug("[AIAnalyst] Rate limit hit, skipping analysis.")
            alert["ai_analysis"] = {"skipped": "rate_limited"}
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
        )

        # Call Ollama Cloud API
        response = requests.post(
            f"{self._base_url}/chat",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self._model,
                "stream": False,
                "format": "json",
                "messages": [
                    {
                        "role": "system",
                        "content": _SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": user_msg,
                    },
                ],
                "options": {
                    "temperature": self.TEMPERATURE,
                    "num_predict": self.MAX_TOKENS,
                },
            },
            timeout=120,
        )

        response.raise_for_status()

        payload = response.json()
        raw_text = (
            payload.get("message", {})
            .get("content", "")
            .strip()
        )

        if not raw_text:
            raise RuntimeError(
                "Ollama Cloud returned an empty response"
            )

        # Parse JSON response
        analysis = self._parse_response(raw_text)
        analysis["provider"] = self._provider
        analysis["model"] = self._model
        analysis["analysed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        analysis["cached"]      = False

        # Cache + write back
        self._cache.set(key, analysis)
        alert["ai_analysis"] = analysis

        # Upgrade severity if LLM says escalate
        if analysis.get("escalate_to_human") and alert.get("severity") != "CRITICAL":
            alert["severity"]     = "CRITICAL"
            alert["description"] += " [LLM: Escalated to CRITICAL]"

        # Downgrade to INFO if high FP confidence (≥ 80%)
        if analysis.get("is_false_positive") and analysis.get("fp_confidence", 0) >= 80:
            alert["severity"] = "INFO"
            alert["status"]   = "FALSE_POSITIVE_SUSPECTED"

        logger.info(
            f"[AIAnalyst] {alert.get('alert_name')} → "
            f"FP={analysis.get('is_false_positive')} "
            f"(fp_conf={analysis.get('fp_confidence')}%) "
            f"threat_conf={analysis.get('threat_confidence')}%"
        )
        return alert

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
