import re
import numpy as np
import joblib
import os
import torch
import torch.nn as nn
from datetime import datetime
from config import config

class LogAutoencoder(nn.Module):
    """
    Simple feed-forward autoencoder used to model typical log-feature vectors.
    The network compresses inputs into a low-dimensional representation and
    reconstructs them for reconstruction-loss based anomaly detection.
    """
    def __init__(self, input_dim):
        super(LogAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16), nn.Tanh(),
            nn.Linear(16, 8), nn.Tanh(),
            nn.Linear(8, 4)
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8), nn.Tanh(),
            nn.Linear(8, 16), nn.Tanh(),
            nn.Linear(16, input_dim)
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))

class ThreatDetector:
    """
    Hybrid detection engine combining rule-based signatures with NLP and
    deep-learning (autoencoder) anomaly detectors.
    """
    def __init__(self, signatures):
        self.signatures = signatures
        
        # NLP components (TF-IDF vectorizer + Isolation Forest)
        self.vectorizer = None
        self.nlp_model = None
        
        # Autoencoder components (scaler + PyTorch model + threshold)
        self.ae_model = None
        self.scaler = None
        self.ae_threshold = 1.0

        self._load_all_models()

    def _load_all_models(self):
        model_dir = "models"
        try:
            # 1) NLP models: TF-IDF vectorizer and isolation forest
            if os.path.exists(os.path.join(model_dir, "nlp_iso_forest.pkl")):
                self.vectorizer = joblib.load(os.path.join(model_dir, "tfidf_vectorizer.pkl"))
                self.nlp_model = joblib.load(os.path.join(model_dir, "nlp_iso_forest.pkl"))
            
            # 2) Autoencoder: scaler, threshold and PyTorch weights
            if os.path.exists(os.path.join(model_dir, "autoencoder.pth")):
                self.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
                with open(os.path.join(model_dir, "threshold.txt"), "r") as f:
                    self.ae_threshold = float(f.read().strip())
                
                self.ae_model = LogAutoencoder(input_dim=3)
                self.ae_model.load_state_dict(torch.load(os.path.join(model_dir, "autoencoder.pth")))
                self.ae_model.eval()
                
            print(f"[INFO] Hybrid Detection Engine Loaded. AE Threshold: {self.ae_threshold:.4f}")
        except Exception as e:
            print(f"[ERROR] Loading Models: {e}")

    # --- Preprocessing Helpers ---
    def _clean_text(self, line):
        """
        Normalize a log line for NLP processing:
        - Remove leading timestamp and process prefix
        - Replace IP addresses and numeric tokens with placeholders
        """
        line = re.sub(r'^\w{3}\s+\d+\s+\d+:\d+:\d+\s+', '', line)
        line = re.sub(r'^[\w\-]+\s+[\w\[\]]+:\s+', '', line)
        line = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP_ADDR', line)
        line = re.sub(r'\d+', 'NUM', line)
        return line.strip()

    def _extract_stats(self, line):
        """
        Extract simple numeric features from a log line:
        - length, Shannon entropy, and number of digit characters
        """
        l = len(line)
        if l == 0: return [0, 0, 0]
        prob = [float(line.count(c)) / l for c in dict.fromkeys(list(line))]
        entropy = -sum([p * np.log2(p) for p in prob])
        digits = sum(c.isdigit() for c in line)
        return [l, entropy, digits]

    def analyze(self, log_line):
        """
        Main analysis pipeline:
        1) Fast rule-based signature check
        2) Slower AI checks (NLP + Autoencoder)
        3) Combine results (ensemble logic) to produce a structured alert
        """
        # 1. Rule-based detection (fast)
        alert = self._rule_based_detect(log_line)
        
        # 2. AI-based checks (slower)
        nlp_anomaly, nlp_score = self._check_nlp(log_line)
        ae_anomaly, ae_score = self._check_autoencoder(log_line)
        
        # --- Ensemble decision logic ---
        # If a signature matched, augment severity when AI confirms
        if alert:
            if nlp_anomaly or ae_anomaly:
                alert["severity"] = "CRITICAL"
                alert["description"] += f" [AI Confirmed: NLP({nlp_score:.2f}) AE({ae_score:.2f})]"
            return alert

        # If no rule matched, let AI detectors determine zero-day anomalies
        if nlp_anomaly and ae_anomaly:
            # Both detectors flagged -> high confidence anomaly
            return self._create_ai_alert("Critical AI Anomaly", "CRITICAL", log_line, nlp_score, ae_score)
        
        elif nlp_anomaly:
            # Semantic anomaly detected by NLP
            return self._create_ai_alert("Semantic Anomaly (NLP)", "HIGH", log_line, nlp_score, ae_score)
            
        elif ae_anomaly:
            # Structural anomaly detected by autoencoder
            return self._create_ai_alert("Structural Anomaly (AE)", "HIGH", log_line, nlp_score, ae_score)

        return None

    def _check_nlp(self, log_line):
        """
        Run the NLP isolation-forest detector.
        Returns (is_anomaly: bool, score: float). Negative scores indicate anomalies.
        """
        if not self.nlp_model: return False, 0
        try:
            clean = self._clean_text(log_line)
            vec = self.vectorizer.transform([clean])
            score = self.nlp_model.decision_function(vec)[0]
            # score < 0 => anomalous
            return score < 0, score
        except:
            return False, 0

    def _check_autoencoder(self, log_line):
        """
        Compute reconstruction loss from the autoencoder and compare against threshold.
        Returns (is_anomaly: bool, loss: float).
        """
        if not self.ae_model: return False, 0
        try:
            stats = self._extract_stats(log_line)
            stats_scaled = self.scaler.transform([stats])
            inp = torch.tensor(stats_scaled, dtype=torch.float32)
            with torch.no_grad():
                out = self.ae_model(inp)
                loss = torch.mean((inp - out)**2).item()
            return loss > self.ae_threshold, loss
        except:
            return False, 0

    def _create_ai_alert(self, title, severity, log, nlp, ae):
        """
        Build a structured alert originating from AI detectors.
        """
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert_name": title,
            "severity": severity,
            "mitre_attck_id": "T1204 (Zero-day)",
            "description": f"AI Detection: NLP Score={nlp:.2f}, AE Loss={ae:.4f}",
            "raw_log": log.strip(),
            "ml_anomaly_score": round(ae, 4),  # use AE loss as the representative score
            "ip_address": "N/A",
            "mitigation_command": "Manual Investigation Required"
        }

    def _rule_based_detect(self, log_line):
        """
        Iterate configured signature patterns and produce a structured alert
        on first match. IP extraction is performed when the signature declares it.
        """
        for sig in self.signatures:
            match = re.search(sig["pattern"], log_line, re.IGNORECASE)
            if match:
                return {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "alert_name": sig["name"],
                    "severity": sig["severity"],
                    "mitre_attck_id": sig["mitre_id"],
                    "description": sig["description"],
                    "raw_log": log_line.strip(),
                    "status": "DETECTED",
                    "ip_address": match.group(1) if sig.get("extract_ip") and match.lastindex else "N/A"
                }
        return None