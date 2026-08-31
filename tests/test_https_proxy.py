import os
from pathlib import Path
from unittest.mock import patch

from flask import Flask, jsonify, request

from src.dashboard_auth import init_proxy


ROOT = Path(__file__).resolve().parents[1]


def test_https_proxy():
    environment = {
        "DASHBOARD_TRUSTED_PROXY_HOPS": "1",
        "DASHBOARD_TRUSTED_HOSTS": "localhost",
    }
    with patch.dict(os.environ, environment):
        app = Flask(__name__)
        init_proxy(app)

    @app.get("/")
    def index():
        return jsonify({"host": request.host, "remote": request.remote_addr, "scheme": request.scheme})

    client = app.test_client()
    forwarded = {
        "X-Forwarded-For": "192.0.2.10",
        "X-Forwarded-Host": "localhost",
        "X-Forwarded-Proto": "https",
    }
    response = client.get("/", headers=forwarded)
    assert response.status_code == 200
    assert response.get_json() == {"host": "localhost", "remote": "192.0.2.10", "scheme": "https"}
    assert client.get("/", headers={**forwarded, "X-Forwarded-Host": "evil.example"}).status_code == 400

    with patch.dict(os.environ, {"DASHBOARD_TRUSTED_PROXY_HOPS": "2"}):
        try:
            init_proxy(Flask(__name__))
            raise AssertionError("multiple trusted proxy hops must fail")
        except RuntimeError:
            pass
    with patch.dict(os.environ, {
        "DASHBOARD_TRUSTED_PROXY_HOPS": "1", "DASHBOARD_TRUSTED_HOSTS": "https://evil.example",
    }):
        try:
            init_proxy(Flask(__name__))
            raise AssertionError("invalid trusted host must fail")
        except RuntimeError:
            pass

    compose = (ROOT / "docker-compose.https.yml").read_text(encoding="utf-8")
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "HTTPS_DEPLOYMENT.md").read_text(encoding="utf-8")
    assert 'ports: !reset []' in compose and 'DASHBOARD_COOKIE_SECURE: "true"' in compose
    assert "DASHBOARD_HOST: 0.0.0.0" in compose
    assert "DASHBOARD_TRUSTED_PROXY_HOPS: \"1\"" in compose and "networks:\n      - proxy" in compose
    assert "redir https://localhost{uri} 308" in caddy and "max_size 2MB" in caddy
    assert "reverse_proxy dashboard:5000" in caddy
    assert "/data/caddy/pki/authorities/local/root.crt" in guide


if __name__ == "__main__":
    test_https_proxy()
    print("M22.2 HTTPS reverse-proxy profile passed")
