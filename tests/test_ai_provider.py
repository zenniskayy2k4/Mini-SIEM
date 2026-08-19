import copy
import json

from src.ai_analyst import AIAnalyst
from src.ai_provider import AIProvider, OllamaCloudProvider, build_ai_provider
from src.alert_schema import build_alert


ANALYSIS = {
    "is_false_positive": False,
    "fp_confidence": 5,
    "threat_confidence": 92,
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110.001 - Password Guessing",
    "threat_summary": "Repeated failed authentication was observed.",
    "observed_facts": ["Five failed logins"],
    "analyst_inferences": ["Password guessing is likely"],
    "recommended_playbook": ["Review authentication logs"],
    "ioc_tags": ["192.0.2.10"],
    "escalate_to_human": True,
}


class DummyProvider(AIProvider):
    name = "fixture"
    model = "fixture-model"

    def __init__(self, *, enabled=True, failure=None):
        self.enabled = enabled
        self.failure = failure
        self.calls = []

    def available(self):
        return self.enabled

    def analyze(self, messages, schema):
        self.calls.append((messages, schema))
        if self.failure:
            raise self.failure
        return json.dumps(ANALYSIS)


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"message": {"content": json.dumps(ANALYSIS)}}


def _alert():
    return build_alert(
        alert_name="Provider abstraction fixture",
        severity="HIGH",
        source_type="HIDS_LOG",
        description="Repeated failed authentication",
        ip_address="192.0.2.10",
        timestamp="2026-08-19T00:00:00Z",
    )


def test_ai_provider():
    requests_seen = []

    def opener(url, **kwargs):
        requests_seen.append((url, kwargs))
        return FakeResponse()

    cloud = OllamaCloudProvider("cloud-secret", opener=opener)
    assert cloud.available() is True and cloud.name == "ollama_cloud"
    assert json.loads(cloud.analyze([{"role": "user", "content": "test"}], "json")) == ANALYSIS
    url, request = requests_seen[0]
    assert url == "https://ollama.com/api/chat"
    assert request["json"]["model"] == "gemma4:cloud"
    assert request["json"]["format"] == "json"
    assert request["headers"]["Authorization"] == "Bearer cloud-secret"
    assert request["timeout"] == 120

    assert build_ai_provider(
        "OLLAMA_CLOUD", api_key="", base_url="https://ollama.com/api", model="gemma4:cloud",
    ).available() is False
    for values in (
        {"name": "unknown", "api_key": "x", "base_url": "https://ollama.com/api", "model": "m"},
        {"name": "ollama_cloud", "api_key": "x", "base_url": "http://ollama.test", "model": "m"},
        {"name": "ollama_cloud", "api_key": "x", "base_url": "https://ollama.test", "model": ""},
    ):
        try:
            build_ai_provider(**values)
            raise AssertionError("invalid provider configuration was accepted")
        except ValueError:
            pass

    provider = DummyProvider()
    analyst = AIAnalyst(provider)
    alert = _alert()
    enriched = analyst.enrich_sync(alert)
    analysis = enriched["ai_analysis"]
    assert all(analysis[key] == value for key, value in ANALYSIS.items())
    assert analysis["provider"] == "fixture" and analysis["model"] == "fixture-model"
    assert analysis["cached"] is False and analysis["analysed_at"].endswith("Z")
    assert enriched["ai_disposition"] == "REQUIRES_HUMAN_REVIEW"
    assert len(provider.calls) == 1 and provider.calls[0][1] == "json"
    assert [message["role"] for message in provider.calls[0][0]] == ["system", "user"]

    cached_alert = copy.deepcopy(alert)
    cached_alert.pop("ai_analysis", None)
    cached = analyst.enrich_sync(cached_alert)["ai_analysis"]
    assert cached["cached"] is True and cached["provider"] == "fixture"
    assert len(provider.calls) == 1
    assert analyst.health_status()["provider"] == "fixture"
    analyst.shutdown()

    failed_provider = DummyProvider(failure=RuntimeError("offline"))
    failed_analyst = AIAnalyst(failed_provider)
    failure = failed_analyst.enrich_sync(_alert())["ai_analysis"]
    assert failure == {"error": "offline", "provider": "fixture", "model": "fixture-model"}
    assert failed_analyst.health_status()["available"] is False
    failed_analyst.shutdown()

    disabled_provider = DummyProvider(enabled=False)
    disabled_analyst = AIAnalyst(disabled_provider)
    untouched = _alert()
    assert disabled_analyst.enrich_sync(untouched) is untouched
    assert disabled_provider.calls == [] and disabled_analyst.health_status()["enabled"] is False
    disabled_analyst.shutdown()


if __name__ == "__main__":
    test_ai_provider()
    print("M15.1 AI provider interface passed")
