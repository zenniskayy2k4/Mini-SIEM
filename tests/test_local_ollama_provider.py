import json
from pathlib import Path
from unittest.mock import patch

from src.ai_analyst import AIAnalyst
from src.ai_provider import OllamaLocalProvider, build_ai_provider
from src.alert_schema import build_alert


ANALYSIS = {
    "is_false_positive": False,
    "fp_confidence": 10,
    "threat_confidence": 85,
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110.001 - Password Guessing",
    "threat_summary": "Local analysis fixture.",
    "observed_facts": ["Failed logins"],
    "analyst_inferences": [],
    "recommended_playbook": ["Review source"],
    "ioc_tags": ["192.0.2.20"],
    "escalate_to_human": True,
}


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_local_ollama_provider():
    health_calls, chat_calls = [], []

    def health(url, **kwargs):
        health_calls.append((url, kwargs))
        return Response({"models": [{"name": "fixture:latest", "model": "fixture:latest"}]})

    def chat(url, **kwargs):
        chat_calls.append((url, kwargs))
        return Response({"message": {"content": json.dumps(ANALYSIS)}})

    provider = OllamaLocalProvider(
        "http://ollama.test:11434/api", "fixture:latest",
        opener=chat, health_opener=health,
    )
    assert provider.available() is True and provider.available() is True
    assert health_calls == [("http://ollama.test:11434/api/tags", {"timeout": 2})]
    analyst = AIAnalyst(provider)
    alert = build_alert(
        alert_name="Local Ollama fixture", severity="HIGH", source_type="HIDS_LOG",
        description="Repeated failed logins", ip_address="192.0.2.20",
        timestamp="2026-08-20T00:00:00Z",
    )
    result = analyst.enrich_sync(alert)
    assert result["ai_analysis"]["provider"] == "ollama_local"
    assert result["ai_analysis"]["model"] == "fixture:latest"
    assert result["ai_analysis"]["threat_summary"] == "Local analysis fixture."
    assert len(chat_calls) == 1 and chat_calls[0][0] == "http://ollama.test:11434/api/chat"
    request = chat_calls[0][1]
    assert request["json"]["model"] == "fixture:latest"
    assert request["headers"] == {"Content-Type": "application/json"}
    assert "Authorization" not in request["headers"]
    assert analyst.health_status() == {
        "enabled": True, "provider": "ollama_local", "model": "fixture:latest",
        "available": True, "last_successful_enrichment": result["ai_analysis"]["analysed_at"],
        "last_failure": None, "busy": False, "backlog": 0,
    }
    analyst.shutdown()

    missing = OllamaLocalProvider(
        "http://ollama.test:11434/api", "missing:latest",
        health_opener=lambda *_args, **_kwargs: Response({"models": []}),
    )
    assert missing.available() is False
    with patch("src.ai_analyst.logger.warning"):
        unavailable_analyst = AIAnalyst(missing)
    untouched = build_alert(
        alert_name="Unavailable local", severity="HIGH", source_type="HIDS_LOG",
        description="No local model",
    )
    assert unavailable_analyst.enrich_sync(untouched) is untouched
    assert untouched["ai_analysis"] is None
    unavailable_analyst.shutdown()

    built = build_ai_provider(
        "ollama_local", api_key="unused", base_url="https://ollama.com/api",
        model="cloud:unused", local_base_url="http://localhost:11434/api",
        local_model="custom:7b",
    )
    assert isinstance(built, OllamaLocalProvider)
    assert built.base_url == "http://localhost:11434/api" and built.model == "custom:7b"

    for url in ("file:///tmp/ollama", "http://user:password@ollama.test/api", "http://ollama.test/api?q=1"):
        try:
            OllamaLocalProvider(url, "fixture:latest")
            raise AssertionError("invalid local Ollama URL was accepted")
        except ValueError:
            pass

    source = Path("src/ai_provider.py").read_text(encoding="utf-8")
    environment = Path(".env.example").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    assert '"/pull"' not in source and "'/pull'" not in source
    assert "OLLAMA_LOCAL_BASE_URL=" in environment and "OLLAMA_LOCAL_MODEL=" in environment
    assert "does not install Ollama" in readme and "approximately 3.3 GB" in readme


if __name__ == "__main__":
    test_local_ollama_provider()
    print("M15.2 optional local Ollama provider passed")
