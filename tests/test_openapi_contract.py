import re
from pathlib import Path

import yaml

import dashboard


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "openapi-v1.yaml"
HTTP_METHODS = {"get", "post", "patch", "put", "delete"}


def _openapi_path(flask_path):
    return re.sub(r"<(?:[^:]+:)?([^>]+)>", r"{\1}", flask_path)


def _resolve(document, reference):
    assert reference.startswith("#/")
    value = document
    for segment in reference[2:].split("/"):
        value = value[segment.replace("~1", "/").replace("~0", "~")]
    return value


def _operations(document):
    return {
        (path, method): operation
        for path, path_item in document["paths"].items()
        for method, operation in path_item.items()
        if method in HTTP_METHODS
    }


def test_openapi_contract():
    document = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    assert document["openapi"] == "3.1.0"
    assert document["x-default-request-body-limit-bytes"] == 2 * 1024 * 1024

    actual = {
        (_openapi_path(rule.rule), method.lower())
        for rule in dashboard.app.url_map.iter_rules()
        if rule.endpoint.startswith("v1_")
        for method in rule.methods - {"HEAD", "OPTIONS"}
    }
    operations = _operations(document)
    assert set(operations) == actual

    operation_ids = []
    for (_, method), operation in operations.items():
        operation_ids.append(operation["operationId"])
        assert operation["x-required-role"] in {"viewer", "analyst", "admin"}
        assert "401" in operation["responses"]
        security = operation.get("security", document["security"])
        assert any("sessionCookie" in requirement for requirement in security)
        if method in {"post", "patch", "put", "delete"}:
            assert any(
                {"sessionCookie", "csrfToken"} <= set(requirement)
                for requirement in security
            )
    assert len(operation_ids) == len(set(operation_ids))

    for response_name in (
        "BadRequest", "Unauthorized", "Forbidden", "NotFound",
        "Conflict", "PayloadTooLarge", "Unavailable",
    ):
        schema = document["components"]["responses"][response_name]["content"][
            "application/json"
        ]["schema"]
        assert schema == {"$ref": "#/components/schemas/Error"}
    assert document["components"]["schemas"]["Error"]["required"] == ["error"]

    def check_references(value):
        if isinstance(value, dict):
            if "$ref" in value:
                _resolve(document, value["$ref"])
            for child in value.values():
                check_references(child)
        elif isinstance(value, list):
            for child in value:
                check_references(child)

    check_references(document)

    search = operations[("/api/v1/alerts/search", "get")]
    parameters = {
        _resolve(document, parameter["$ref"])["name"]: _resolve(document, parameter["$ref"])
        for parameter in search["parameters"]
        if "$ref" in parameter
    }
    assert parameters["page"]["schema"] == {"type": "integer", "minimum": 1, "default": 1}
    assert parameters["page_size"]["schema"] == {
        "type": "integer", "minimum": 1, "maximum": 200, "default": 50,
    }
    assert search["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AlertPage"
    }

    assert {
        (path, method): operation["x-request-body-limit-bytes"]
        for (path, method), operation in operations.items()
        if "x-request-body-limit-bytes" in operation
    } == {
        ("/api/v1/detection-exceptions", "post"): 8192,
        ("/api/v1/alert-suppression-policies", "post"): 8192,
        ("/api/v1/alerts/{alert_id}/feedback", "post"): 8192,
        ("/api/v1/assets", "post"): 65536,
        ("/api/v1/assets/{asset_id}", "patch"): 65536,
    }
    assert operations[("/api/v1/analytics/kpis", "get")]["x-max-range-days"] == 366
    assert 'for test_file in tests/test_*.py' in (
        ROOT / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")


if __name__ == "__main__":
    test_openapi_contract()
    print("M28.3 OpenAPI contract passed")
