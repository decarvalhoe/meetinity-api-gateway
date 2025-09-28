import os
import sys
import pytest
import requests
from unittest.mock import Mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.app import create_app  # noqa: E402


def _create_app_without_cors_origins(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    monkeypatch.setenv("USER_SERVICE_URL", "http://upstream")
    monkeypatch.setenv("JWT_SECRET", "secret")
    monkeypatch.setenv("RATE_LIMIT_AUTH", "10/minute")

    mock_resp = Mock()
    mock_resp.status_code = 200
    monkeypatch.setattr(
        "src.app.requests.get", lambda *args, **kwargs: mock_resp
    )

    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def app(monkeypatch):
    os.environ["USER_SERVICE_URL"] = "http://upstream"
    os.environ["CORS_ORIGINS"] = ""
    os.environ["JWT_SECRET"] = "secret"
    os.environ["RATE_LIMIT_AUTH"] = "10/minute"

    mock_resp = Mock()
    mock_resp.status_code = 200
    monkeypatch.setattr(
        "src.app.requests.get", lambda *args, **kwargs: mock_resp
    )

    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    with app.test_client() as client:
        yield client


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "up"
    assert response.json["upstreams"]["user_service"] == "up"


def test_health_upstream_down(client, monkeypatch):
    def fail_health(*args, **kwargs):
        raise requests.RequestException()

    monkeypatch.setattr("src.app.requests.get", fail_health)

    response = client.get("/health")
    assert response.status_code == 503
    assert response.json["status"] == "down"
    assert response.json["upstreams"]["user_service"] == "down"


def test_users_requires_jwt(client):
    response = client.get("/api/users/me")
    assert response.status_code == 401


def test_options_users_without_authorization(client):
    response = client.options("/api/users")
    assert response.status_code != 401


def test_auth_proxy_failure(client, monkeypatch):
    def fail_request(*args, **kwargs):
        raise requests.RequestException()
    monkeypatch.setattr(
        "src.routes.proxy.requests.request", fail_request
    )
    response = client.post("/api/auth/login")
    assert response.status_code == 502


def test_proxy_preserves_duplicate_query_params(client, monkeypatch):
    captured = {}

    def fake_request(*args, **kwargs):
        captured["params"] = kwargs.get("params")
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b"{}"
        mock_resp.headers = {}
        return mock_resp

    monkeypatch.setattr(
        "src.routes.proxy.requests.request", fake_request
    )

    response = client.get("/api/auth/tokens?tag=a&tag=b")

    assert response.status_code == 200
    assert captured["params"] == [("tag", "a"), ("tag", "b")]


def test_cors_allows_any_origin_when_env_absent(monkeypatch):
    app = _create_app_without_cors_origins(monkeypatch)
    origin = "https://example.com"
    with app.test_client() as client:
        response = client.get("/health", headers={"Origin": origin})

    assert response.headers.get("Access-Control-Allow-Origin") == origin


def test_cors_allows_another_origin_when_env_absent(monkeypatch):
    app = _create_app_without_cors_origins(monkeypatch)
    origin = "https://another.test"
    with app.test_client() as client:
        response = client.get("/health", headers={"Origin": origin})

    assert response.headers.get("Access-Control-Allow-Origin") == origin
