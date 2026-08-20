import json
import threading

from src.ai_analyst import AIAnalyst
from src.ai_provider import AIProvider, FallbackAIProvider, build_ai_provider
from src.alert_schema import build_alert


ANALYSIS = {
    "is_false_positive": False,
    "fp_confidence": 5,
    "threat_confidence": 90,
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110.001 - Password Guessing",
    "threat_summary": "Fallback analysis fixture.",
    "observed_facts": ["Failed logins"],
    "analyst_inferences": [],
    "recommended_playbook": ["Review source"],
    "ioc_tags": ["192.0.2.30"],
    "escalate_to_human": True,
}


class FixtureProvider(AIProvider):
    def __init__(self, name, model, *, failure=None):
        self.name = name
        self.model = model
        self.failure = failure
        self.calls = 0

    def available(self):
        return True

    def analyze(self, messages, schema):
        self.calls += 1
        if self.failure:
            raise self.failure
        return json.dumps(ANALYSIS)


def _alert(name):
    return build_alert(
        alert_name=name, severity="HIGH", source_type="HIDS_LOG",
        description="Repeated failed logins", ip_address="192.0.2.30",
        timestamp="2026-08-20T00:00:00Z",
    )


def test_ai_provider_fallback():
    cloud = FixtureProvider("ollama_cloud", "cloud:model", failure=RuntimeError("secret failure"))
    local = FixtureProvider("ollama_local", "local:model")
    analyst = AIAnalyst(FallbackAIProvider(cloud, local))
    result = analyst.enrich_sync(_alert("Fallback success"))
    assert cloud.calls == 1 and local.calls == 1
    assert result["ai_analysis"]["provider"] == "ollama_local"
    assert result["ai_analysis"]["model"] == "local:model"
    assert result["ai_analysis"]["threat_summary"] == "Fallback analysis fixture."
    assert analyst.health_status()["fallback"] == {
        "chain": ["ollama_cloud", "ollama_local"],
        "last_provider": "ollama_local",
        "used": True,
        "attempts": [
            {"provider": "ollama_cloud", "status": "failed"},
            {"provider": "ollama_local", "status": "success"},
        ],
    }
    analyst.shutdown()

    primary = FixtureProvider("ollama_cloud", "cloud:model")
    unused = FixtureProvider("ollama_local", "local:model")
    primary_analyst = AIAnalyst(FallbackAIProvider(primary, unused))
    assert primary_analyst.enrich_sync(_alert("Primary success"))["ai_analysis"]["provider"] == "ollama_cloud"
    assert primary.calls == 1 and unused.calls == 0
    primary_analyst.shutdown()

    first = FixtureProvider("ollama_cloud", "cloud:model", failure=RuntimeError("cloud secret"))
    second = FixtureProvider("ollama_local", "local:model", failure=RuntimeError("local secret"))
    failed_analyst = AIAnalyst(FallbackAIProvider(first, second))
    callback_results, completed = [], threading.Event()
    failed_analyst.enrich_async(
        _alert("All providers fail"),
        lambda alert: (callback_results.append(alert), completed.set()),
    )
    assert completed.wait(2) and len(callback_results) == 1
    assert first.calls == 1 and second.calls == 1
    failure = callback_results[0]["ai_analysis"]
    assert failure["error"] == "All configured AI providers are unavailable"
    assert "secret" not in json.dumps(failure)
    assert [item["status"] for item in failed_analyst.health_status()["fallback"]["attempts"]] == [
        "failed", "failed",
    ]
    failed_analyst.shutdown()

    built = build_ai_provider(
        "ollama_cloud", fallback_name="ollama_local", api_key="key",
        base_url="https://ollama.com/api", model="cloud:model",
        local_base_url="http://localhost:11434/api", local_model="local:model",
    )
    assert isinstance(built, FallbackAIProvider)
    try:
        build_ai_provider(
            "ollama_cloud", fallback_name="ollama_cloud", api_key="key",
            base_url="https://ollama.com/api", model="cloud:model",
        )
        raise AssertionError("duplicate fallback provider was accepted")
    except ValueError:
        pass


if __name__ == "__main__":
    test_ai_provider_fallback()
    print("M15.3 bounded AI provider fallback passed")
