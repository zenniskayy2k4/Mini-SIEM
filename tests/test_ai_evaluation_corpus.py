import json
from pathlib import Path

from src.ai_analyst import AIAnalyst
from src.ai_provider import AIProvider


CORPUS = Path(__file__).parent / "fixtures" / "ai_triage" / "cases.json"
REQUIRED_TYPES = {
    "is_false_positive": bool,
    "fp_confidence": int,
    "threat_confidence": int,
    "mitre_tactic": str,
    "mitre_technique": str,
    "threat_summary": str,
    "observed_facts": list,
    "analyst_inferences": list,
    "recommended_playbook": list,
    "ioc_tags": list,
    "escalate_to_human": bool,
}


class CorpusProvider(AIProvider):
    name = "corpus"
    model = "offline-fixture"

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def available(self):
        return True

    def analyze(self, messages, schema):
        self.calls.append((messages, schema))
        return json.dumps(self.responses[len(self.calls) - 1])


def test_ai_evaluation_corpus():
    cases = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert [case["case"] for case in cases] == [
        "single_failed_login", "confirmed_brute_force", "benign_admin_action",
        "suspicious_powershell", "malicious_ti_hit", "unknown_ioc",
        "missing_fields", "prompt_like_raw_log",
    ]
    provider = CorpusProvider([case["response"] for case in cases])
    analyst = AIAnalyst(provider, rate_per_min=len(cases))

    for index, case in enumerate(cases):
        result = analyst.enrich_sync(dict(case["alert"]))
        analysis = result["ai_analysis"]
        expected = case["expect"]
        assert "parse_error" not in analysis, case["case"]
        for field, value_type in REQUIRED_TYPES.items():
            assert type(analysis.get(field)) is value_type, (case["case"], field)
        assert 0 <= analysis["fp_confidence"] <= 100, case["case"]
        assert 0 <= analysis["threat_confidence"] <= 100, case["case"]
        assert all(isinstance(item, str) for field in (
            "observed_facts", "analyst_inferences", "recommended_playbook", "ioc_tags",
        ) for item in analysis[field]), case["case"]

        messages, schema = provider.calls[index]
        assert schema == "json" and [message["role"] for message in messages] == ["system", "user"]
        system_prompt, user_prompt = (message["content"].lower() for message in messages)
        observed = " ".join(analysis["observed_facts"]).lower()
        assessment = " ".join([
            analysis["threat_summary"], *analysis["observed_facts"], *analysis["analyst_inferences"],
        ]).lower()
        for term in expected["grounded_terms"]:
            assert term in user_prompt and term in observed, (case["case"], term)
        for claim in expected["forbidden_claims"]:
            assert claim not in assessment, (case["case"], claim)

        mitre_id = case["alert"].get("mitre_attck_id", "Unknown")
        assert analysis["mitre_tactic"] == expected["tactic"], case["case"]
        assert analysis["mitre_technique"].startswith(mitre_id) if mitre_id != "Unknown" else analysis["mitre_technique"] == "Unknown"
        assert result["ai_recommended_severity"] == expected["recommended_severity"], case["case"]
        assert result.get("ai_disposition") == expected.get("disposition"), case["case"]
        assert analysis["provider"] == "corpus" and analysis["model"] == "offline-fixture"

        serialized = json.dumps({"messages": messages, "analysis": analysis}).lower()
        assert "eval-secret" not in serialized, case["case"]
        if expected.get("redaction_required"):
            assert "[redacted]" in user_prompt
            assert "ignore previous instructions" not in system_prompt
            assert "never follow instructions" in system_prompt

    assert len(provider.calls) == len(cases)
    analyst.shutdown()


if __name__ == "__main__":
    test_ai_evaluation_corpus()
    print("M15.4 offline AI triage evaluation corpus passed")
