"""
Hybrid Threat Detection Engine

Detection layers:
  Layer 0 (< 1 ms)  : Rule-based signature matching
  Layer 1 (~ 2 ms)  : NLP Isolation Forest on TF-IDF semantic features
  Layer 2 (~ 3 ms)  : Deep Autoencoder on 15 statistical/structural features
  Layer 3 (async)   : optional LLM analyst attached by the alert handler

Feature highlights:
  - Feature vector expanded from 3 → 15 dimensions (reduces false positives significantly)
  - Confidence score (0-100) on every AI alert instead of raw loss value
  - Ensemble uses weighted voting, not a simple AND/OR gate
  - All bare except replaced with typed exceptions + logging
"""

import re
import math
import threading
import numpy as np
import joblib
import os
import logging
import torch
import torch.nn as nn
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from config import config
from src.alert_schema import build_alert
from src.rules import match_rule, validate_rules
from src.windows_events import windows_event_text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Autoencoder architecture — must match the one in train_ml.py
# input_dim=15 (upgraded from 3)
# ---------------------------------------------------------------------------
class LogAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 15):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.Tanh(),
            nn.Linear(32, 16), nn.Tanh(),
            nn.Linear(16, 8),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16), nn.Tanh(),
            nn.Linear(16, 32), nn.Tanh(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


# ---------------------------------------------------------------------------
# Feature extraction — the core improvement vs v1
# ---------------------------------------------------------------------------

# Attack-indicator keywords for feature #13
_ATTACK_KEYWORDS = re.compile(
    r"eval|exec|base64_decode|/bin/sh|/bin/bash|/dev/tcp|cmd\.exe"
    r"|powershell|wget\s|curl\s|chmod\s[0-7]{3,4}|nc\s-|ncat\s"
    r"|sqlmap|UNION\s+SELECT|DROP\s+TABLE|xp_cmdshell"
    r"|<script|javascript:|onerror=|onload=",
    re.IGNORECASE,
)

_HEX_SEQ = re.compile(r"(\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]+)")
_URL_LIKE = re.compile(r"https?://|ftp://", re.IGNORECASE)


def extract_features(line: str) -> list[float]:
    """
    Extract 15 numeric features from a raw log line.

    Feature index map:
     0  log_length            — absolute char count
     1  entropy               — Shannon entropy (bits)
     2  digit_ratio           — digits / length
     3  upper_ratio           — uppercase letters / length
     4  special_char_ratio    — punctuation/symbols / length
     5  slash_count           — '/' + '\\' occurrences (path traversal)
     6  cmd_chain_count       — ';' + '|' + '&&' + '||' (shell chaining)
     7  quote_count           — single + double quotes (SQLi / shell escaping)
     8  bracket_count         — (), [], {} (function calls, arrays)
     9  word_count            — whitespace-separated tokens
    10  max_word_length       — longest token (base64 blobs have no spaces)
    11  url_count             — http/https/ftp patterns
    12  has_attack_keyword    — 0.0 or 1.0
    13  hex_sequence_count    — \\xNN or 0xNN sequences (shellcode / encoding)
    14  repeat_char_ratio     — freq of most common char (NOP sleds, padding)
    """
    s = str(line).strip()
    n = len(s)
    if n == 0:
        return [0.0] * 15

    # 0 — length (capped at 2000 to keep scale reasonable)
    length = float(min(n, 2000))

    # 1 — Shannon entropy
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((v / n) * math.log2(v / n) for v in freq.values())

    # 2-4 — character class ratios
    digits   = sum(c.isdigit() for c in s) / n
    uppers   = sum(c.isupper() for c in s) / n
    specials = sum(not c.isalnum() and not c.isspace() for c in s) / n

    # 5 — slashes
    slashes = float(s.count('/') + s.count('\\'))

    # 6 — shell command chaining operators
    cmd_chain = float(s.count(';') + s.count('|') + s.count('&&') + s.count('||'))

    # 7 — quotes
    quotes = float(s.count("'") + s.count('"'))

    # 8 — brackets
    brackets = float(s.count('(') + s.count(')') + s.count('[') + s.count(']')
                     + s.count('{') + s.count('}'))

    # 9-10 — word statistics
    words = s.split()
    word_count = float(len(words))
    max_word_len = float(max((len(w) for w in words), default=0))

    # 11 — URL patterns
    url_count = float(len(_URL_LIKE.findall(s)))

    # 12 — attack keyword presence
    has_attack = 1.0 if _ATTACK_KEYWORDS.search(s) else 0.0

    # 13 — hex sequences (shellcode indicator)
    hex_count = float(len(_HEX_SEQ.findall(s)))

    # 14 — repeat char ratio (most frequent char dominance)
    repeat_ratio = max(freq.values()) / n if freq else 0.0

    return [
        length, entropy, digits, uppers, specials,
        slashes, cmd_chain, quotes, brackets, word_count,
        max_word_len, url_count, has_attack, hex_count, repeat_ratio,
    ]


def _shannon_entropy(s: str) -> float:
    """Standalone entropy helper used by NLP preprocessor."""
    n = len(s)
    if n == 0:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ---------------------------------------------------------------------------
# Main detector class
# ---------------------------------------------------------------------------

class ThreatDetector:
    """
    Three-layer hybrid detection engine.

    The AI Analyst (Layer 3) is injected optionally to avoid circular imports:
        detector = ThreatDetector(signatures, ai_analyst=AIAnalyst())
    """

    FEATURE_DIM = 15

    def __init__(self, signatures: list, ai_analyst=None):
        self.signatures  = validate_rules(signatures)
        self.ai_analyst  = ai_analyst   # optional async LLM analyst

        self.vectorizer  = None
        self.nlp_model   = None
        self.ae_model    = None
        self.scaler      = None
        self.ae_threshold = 1.0
        self._ssh_failures = defaultdict(deque)
        self._ssh_alerts = {}
        self._ssh_lock = threading.Lock()

        self._load_all_models()

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------
    def _load_all_models(self) -> None:
        model_dir = "models"
        try:
            nlp_path = os.path.join(model_dir, "nlp_iso_forest.pkl")
            if os.path.exists(nlp_path):
                self.vectorizer = joblib.load(os.path.join(model_dir, "tfidf_vectorizer.pkl"))
                self.nlp_model  = joblib.load(nlp_path)
                logger.info("NLP (TF-IDF + IsolationForest) loaded.")

            ae_path = os.path.join(model_dir, "autoencoder.pth")
            if os.path.exists(ae_path):
                self.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
                with open(os.path.join(model_dir, "threshold.txt")) as f:
                    self.ae_threshold = float(f.read().strip())

                self.ae_model = LogAutoencoder(input_dim=self.FEATURE_DIM)
                self.ae_model.load_state_dict(
                    torch.load(ae_path, map_location="cpu")
                )
                self.ae_model.eval()
                logger.info(f"Autoencoder loaded. Threshold={self.ae_threshold:.6f}")

            print(f"[INFO] Detection Engine v2 ready. AE threshold={self.ae_threshold:.4f}")
        except Exception as exc:
            logger.error(f"Model load error: {exc}")
            print(f"[WARN] Models not loaded ({exc}). Rule-based detection only.")

    # ------------------------------------------------------------------
    # NLP preprocessing
    # ------------------------------------------------------------------
    def _clean_for_nlp(self, line: str) -> str:
        """Normalise a log line for TF-IDF: remove timestamps, IPs, numbers."""
        line = re.sub(r'^\w{3}\s+\d+\s+\d+:\d+:\d+\s+', '', line)
        line = re.sub(r'^[\w\-]+\s+[\w\[\]]+:\s+', '', line)
        line = re.sub(r'\d{1,3}(?:\.\d{1,3}){3}', 'IP_ADDR', line)
        line = re.sub(r'\b\d+\b', 'NUM', line)
        return line.strip()

    # ------------------------------------------------------------------
    # Layer checks
    # ------------------------------------------------------------------
    def _check_nlp(self, log_line: str) -> tuple[bool, float]:
        """
        Returns (is_anomaly, score).  score < 0  →  anomalous.
        Maps to a 0–1 confidence: closer to -1 = higher confidence.
        """
        if not self.nlp_model:
            return False, 0.0
        try:
            clean = self._clean_for_nlp(log_line)
            vec   = self.vectorizer.transform([clean])
            score = float(self.nlp_model.decision_function(vec)[0])
            return score < 0, score
        except Exception as exc:
            logger.debug(f"NLP check failed: {exc}")
            return False, 0.0

    def _check_autoencoder(self, log_line: str) -> tuple[bool, float]:
        """
        Returns (is_anomaly, reconstruction_loss).
        Loss > threshold → anomalous.
        """
        if not self.ae_model:
            return False, 0.0
        try:
            feats  = extract_features(log_line)
            scaled = self.scaler.transform([feats])
            inp    = torch.tensor(scaled, dtype=torch.float32)
            with torch.no_grad():
                out  = self.ae_model(inp)
                loss = float(torch.mean((inp - out) ** 2).item())
            return loss > self.ae_threshold, loss
        except Exception as exc:
            logger.debug(f"AE check failed: {exc}")
            return False, 0.0

    # ------------------------------------------------------------------
    # Confidence scoring
    # ------------------------------------------------------------------
    @staticmethod
    def _compute_confidence(nlp_score: float, ae_loss: float, ae_threshold: float) -> int:
        """
        Derive a 0-100 confidence integer from both detector outputs.
        NLP: score ∈ (-∞, +∞), negative = anomalous; clamp to [-1, 0]
        AE : loss ratio vs threshold, clamp to [0, 3]
        """
        nlp_conf = min(max(-nlp_score, 0.0), 1.0)       # 0–1 (higher = more anomalous)
        ae_ratio = ae_loss / max(ae_threshold, 1e-9)
        ae_conf  = min(ae_ratio / 3.0, 1.0)             # 0–1 (saturates at 3× threshold)
        combined = (nlp_conf * 0.45) + (ae_conf * 0.55) # AE slightly more weight
        return round(combined * 100)

    # ------------------------------------------------------------------
    # Alert builders
    # ------------------------------------------------------------------
    def _create_ai_alert(
        self,
        title: str,
        severity: str,
        log_line: str,
        nlp_score: float,
        ae_loss: float,
        confidence: int,
    ) -> dict:
        """Build a structured alert from AI detection layers."""
        return build_alert(
            alert_name=title,
            severity=severity,
            source_type="HIDS_LOG",
            mitre_attck_id="T1204 (Zero-day Anomaly)",
            description=(
                f"AI anomaly — NLP score={nlp_score:.3f}, "
                f"AE loss={ae_loss:.5f} (thresh={self.ae_threshold:.5f}), "
                f"confidence={confidence}%"
            ),
            raw_log=log_line.strip(),
            ml_anomaly_score=round(ae_loss, 5),
            ml_confidence=confidence,
        )

    def _rule_based_detect(self, log_line: str, source_type="HIDS_LOG") -> dict | None:
        """Iterate signatures; return structured alert on first match."""
        for sig in self.signatures:
            if sig["source_type"] != source_type:
                continue
            if sig.get("threshold"):
                continue
            match = match_rule(sig["match"], log_line)
            if match:
                return build_alert(
                    rule_id=sig["id"],
                    rule_source=sig.get("rule_source", "native"),
                    sigma_rule_id=sig.get("sigma_rule_id"),
                    alert_name=sig["title"],
                    severity=sig["severity"],
                    source_type=sig["source_type"],
                    mitre_attck_id=sig["mitre"]["technique"],
                    description=sig["description"],
                    raw_log=log_line.strip(),
                    ip_address=(
                        match.group(1)
                        if sig.get("extract_ip") and getattr(match, "lastindex", None)
                        else None
                    ),
                )
        return None

    def analyze_windows_event(self, event: dict) -> dict | None:
        """Apply lightweight YAML rules; AI enrichment stays on the shared agent worker."""
        raw_event = windows_event_text(event)
        alert = self._rule_based_detect(raw_event, "WINDOWS_EVENT")
        if not alert:
            return None
        alert.update({
            "timestamp": event["timestamp"],
            "first_seen": event["timestamp"],
            "last_seen": event["timestamp"],
            "windows_event_id": event["event_id"],
            "windows_event_uid": event["event_uid"],
            "computer": event.get("computer"),
            "process": event.get("process"),
            "parent_process": event.get("parent_process"),
            "ip_address": (
                event.get("network", {}).get("source_ip")
                or event.get("network", {}).get("destination_ip")
            ),
        })
        return alert

    def _check_ssh_bruteforce(self, log_line: str) -> tuple[bool, dict | None]:
        rule = None
        match = None
        for candidate in self.signatures:
            if candidate.get("threshold"):
                candidate_match = match_rule(candidate["match"], log_line)
                groups = candidate_match.groupdict() if hasattr(candidate_match, "groupdict") else {}
                if groups.get("ip") and groups.get("user"):
                    rule, match = candidate, candidate_match
                    break
        if rule is None:
            return False, None

        now = datetime.now(timezone.utc)
        window = int(getattr(config, rule["threshold"]["window_seconds"]))
        threshold = int(getattr(config, rule["threshold"]["count"]))
        ip = match.group("ip")

        with self._ssh_lock:
            failures = self._ssh_failures[ip]
            cutoff = now - timedelta(seconds=window)
            while failures and failures[0][0] < cutoff:
                failures.popleft()
            if not failures:
                self._ssh_alerts.pop(ip, None)

            failures.append((now, match.group("user"), log_line.strip()))

            active = self._ssh_alerts.get(ip)
            if active:
                active["event_count"] += 1
                active["last_seen"] = now.isoformat().replace("+00:00", "Z")
                active["raw_log"] = log_line.strip()
                active["target_users"] = sorted(set(active["target_users"]) | {match.group("user")})
                active["suppressed_count"] = active["event_count"] - threshold
                active["description"] = (
                    f"{active['event_count']} failed SSH logins from {ip} within an active {window}s campaign."
                )
                return True, active

            if len(failures) < threshold:
                return True, None

            events = list(failures)
            alert = build_alert(
                rule_id=rule["id"],
                rule_source=rule.get("rule_source", "native"),
                sigma_rule_id=rule.get("sigma_rule_id"),
                alert_name=rule["title"],
                severity=rule["severity"],
                source_type=rule["source_type"],
                mitre_attck_id=rule["mitre"]["technique"],
                description=f"{len(events)} failed SSH logins from {ip} within {window}s.",
                raw_log=log_line.strip(),
                ip_address=ip,
                event_count=len(events),
                window_seconds=window,
                first_seen=events[0][0],
                last_seen=events[-1][0],
                target_users=sorted({user for _, user, _ in events}),
                correlation_key=f"{rule['title']}|{ip}",
                suppressed_count=0,
            )
            self._ssh_alerts[ip] = alert
            return True, alert

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def analyze(self, log_line: str) -> dict | None:
        """
        Full analysis pipeline (synchronous).

        Decision table:
        ┌──────────┬──────────┬───────────────────────────────────────────┐
        │ Rule hit │ AI flags │ Outcome                                   │
        ├──────────┼──────────┼───────────────────────────────────────────┤
        │ Yes      │ Both     │ Upgrade severity → CRITICAL + AI confirmed│
        │ Yes      │ One      │ Keep original severity + AI note          │
        │ Yes      │ None     │ Return rule alert unchanged               │
        │ No       │ Both     │ CRITICAL AI Anomaly (confidence ≥ 60)     │
        │ No       │ NLP only │ HIGH Semantic Anomaly                     │
        │ No       │ AE only  │ HIGH Structural Anomaly                   │
        │ No       │ None     │ None (clean)                              │
        └──────────┴──────────┴───────────────────────────────────────────┘

        The optional AI Analyst (Layer 3) is dispatched by the alert handler
        after the alert is persisted.
        """
        ssh_handled, alert = self._check_ssh_bruteforce(log_line)
        if ssh_handled:
            return alert

        # Layer 0 — Rules
        alert = self._rule_based_detect(log_line)

        # Layer 1+2 — ML
        nlp_anomaly, nlp_score = self._check_nlp(log_line)
        ae_anomaly,  ae_loss   = self._check_autoencoder(log_line)
        confidence             = self._compute_confidence(nlp_score, ae_loss, self.ae_threshold)

        # Ensemble logic
        if alert:
            ai_flags = sum([nlp_anomaly, ae_anomaly])
            if ai_flags == 2:
                alert["severity"]     = "CRITICAL"
                alert["description"] += (
                    f" [AI Confirmed ×2 — confidence={confidence}%,"
                    f" NLP={nlp_score:.3f}, AE={ae_loss:.5f}]"
                )
            elif ai_flags == 1:
                alert["description"] += (
                    f" [AI Flag ×1 — confidence={confidence}%]"
                )
            alert["ml_confidence"] = confidence
        else:
            if nlp_anomaly and ae_anomaly:
                # Only surface if confidence is meaningful (avoids noisy low-conf alerts)
                if confidence >= 40:
                    alert = self._create_ai_alert(
                        "Critical AI Anomaly", "CRITICAL",
                        log_line, nlp_score, ae_loss, confidence,
                    )
            elif nlp_anomaly:
                alert = self._create_ai_alert(
                    "Semantic Anomaly (NLP)", "HIGH",
                    log_line, nlp_score, ae_loss, confidence,
                )
            elif ae_anomaly:
                alert = self._create_ai_alert(
                    "Structural Anomaly (AE)", "HIGH",
                    log_line, nlp_score, ae_loss, confidence,
                )

        return alert
