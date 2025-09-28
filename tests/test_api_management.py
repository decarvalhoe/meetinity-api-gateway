import os
import os
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.app import create_app  # noqa: E402


def _configure_base_env(monkeypatch):
    monkeypatch.setenv("USER_SERVICE_URL", "http://upstream")
    monkeypatch.setenv("CORS_ORIGINS", "")
    monkeypatch.setenv("JWT_SECRET", "secret")
    monkeypatch.setenv("RATE_LIMIT_AUTH", "20/minute")
    monkeypatch.setenv("RESILIENCE_BACKOFF_FACTOR", "0")


def _patch_proxy(monkeypatch, status_code=200, headers=None):
    headers = headers or {}
    mock_resp = Mock()
    mock_resp.status_code = status_code
    mock_resp.content = b"{}"
    mock_resp.headers = headers
    mock_resp.raw = Mock(headers={})

    session = Mock()
    session.request = Mock(return_value=mock_resp)
    monkeypatch.setattr("src.routes.proxy._get_http_session", lambda: session)
    return mock_resp, session


@pytest.fixture
def app_factory(monkeypatch):
    def _factory(extra_env=None):
        _configure_base_env(monkeypatch)
        if extra_env:
            for key, value in extra_env.items():
                monkeypatch.setenv(key, value)
        _patch_proxy(monkeypatch)
        app = create_app()
        app.config["TESTING"] = True
        return app

    return _factory


def test_versioned_routes_available(app_factory):
    app = app_factory()
    client = app.test_client()

    for path in ("/api/auth/ping", "/v1/api/auth/ping", "/v2/api/auth/ping"):
        response = client.get(path)
        assert response.status_code in {200, 502}


def test_deprecation_headers_emitted(monkeypatch, app_factory):
    extra_env = {
        "API_VERSION_DEPRECATIONS": "v1=true",
        "API_VERSION_SUNSETS": "v1=2024-12-31T00:00:00Z",
        "API_VERSION_WARNINGS": 'v1=299 - "Version v1 deprecated"',
    }
    app = app_factory(extra_env=extra_env)
    client = app.test_client()

    response = client.get("/v1/api/auth/ping")
    assert response.status_code in {200, 502}
    assert response.headers.get("Deprecation") == "true"
    assert response.headers.get("Sunset") == "2024-12-31T00:00:00Z"
    warning_headers = response.headers.getlist("Warning")
    assert any("Version v1 deprecated" in header for header in warning_headers)


def test_docs_endpoint_exports_openapi(app_factory):
    app = app_factory()
    client = app.test_client()

    response = client.get("/docs")
    assert response.status_code == 200
    assert b"openapi" in response.data

    json_response = client.get("/docs?format=json")
    assert json_response.status_code == 200
    payload = json_response.get_json()
    assert payload["info"]["title"] == "Meetinity API Gateway"

    spec_path = Path(app.config["OPENAPI_OUTPUT_PATH"])
    assert spec_path.exists()


def test_analytics_collector_tracks_versions(monkeypatch, app_factory):
    app = app_factory()
    client = app.test_client()

    client.get("/api/auth/session")
    client.get("/v2/api/users")

    analytics = app.extensions["analytics"]
    report = analytics.snapshot()

    assert report.total_requests >= 2
    assert "v1" in report.per_version
    assert "v2" in report.per_version
    assert any("auth" in key for key in report.per_endpoint)
