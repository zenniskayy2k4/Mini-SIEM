"""
ai_analyst.py — Groq LLM Analyst (Layer 3)

Responsibilities:
  - Async triage of HIGH/CRITICAL alerts via Groq API (Llama-3 70B)
  - False-positive assessment with confidence score
  - MITRE tactic/technique mapping suggestion
  - Automated playbook generation tailored to the alert type
  - Alert deduplication: same alert_name is not re-analysed within TTL window

Setup:
  pip install groq
  export GROQ_API_KEY="gsk_..."

The analyst runs in a background thread pool so it never blocks the main
detection pipeline. Results are written back into the alert dict in-place
and also appended to the alert store.
"""

import os
import json
import logging
import threading
import time
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
    Enriches SIEM alerts with Groq LLM analysis in a background thread pool.

    Usage:
        analyst = AIAnalyst()                     # reads GROQ_API_KEY from env
        analyst = AIAnalyst(api_key="gsk_...")    # explicit key

        # Inject into detector
        detector = ThreatDetector(signatures, ai_analyst=analyst)

        # Or call manually
        analyst.enrich_async(alert)    # non-blocking, writes back into alert
        result = analyst.enrich_sync(alert)  # blocking, returns enriched alert
    """

    MODEL       = "llama-3.3-70b-versatile"   # fast + accurate for SecOps
    MAX_TOKENS  = 800
    TEMPERATURE = 0.1   # near-deterministic for structured analysis

    def __init__(
        self,
        api_key:      str | None = None,
        max_workers:  int        = 3,
        cache_ttl:    int        = 120,   # seconds before re-analysing same alert type
        rate_per_min: int        = 10,    # Groq free tier safe limit
    ):
        self._api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        if not self._api_key:
            logger.warning(
                "[AIAnalyst] GROQ_API_KEY not set. "
                "Layer 3 analysis disabled. Set env var to enable."
            )

        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="groq_analyst")
        self._cache    = _TTLCache(maxsize=200, ttl_seconds=cache_ttl)
        self._limiter  = _RateLimiter(rate=rate_per_min, period=60.0)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def enrich_async(self, alert: dict) -> None:
        """
        Submit alert for analysis in a background thread.
        The result is written back into `alert` dict in-place
        and also logged. Never raises.
        """
        if not self._api_key:
            return
        self._executor.submit(self._safe_enrich, alert)

    def enrich_sync(self, alert: dict) -> dict:
        """
        Blocking version — useful for testing or forced triage.
        Returns the enriched alert dict.
        """
        if not self._api_key:
            return alert
        return self._safe_enrich(alert)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _cache_key(self, alert: dict) -> str:
        """Deduplicate by alert_name + severity + source_type (not per raw_log)."""
        return f"{alert.get('alert_name','')}|{alert.get('severity','')}|{alert.get('source_type','')}"

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
            alert["ai_analysis"] = cached
            alert["ai_analysis"]["cached"] = True
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

        # Call Groq API (openai-compatible)
        try:
            from groq import Groq
            client   = Groq(api_key=self._api_key)
            response = client.chat.completions.create(
                model       = self.MODEL,
                max_tokens  = self.MAX_TOKENS,
                temperature = self.TEMPERATURE,
                messages    = [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
            )
            raw_text = response.choices[0].message.content.strip()
        except ImportError:
            raise RuntimeError("groq package not installed. Run: pip install groq")

        # Parse JSON response
        analysis = self._parse_response(raw_text)
        analysis["model"]       = self.MODEL
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


import re  # needed by _parse_response
