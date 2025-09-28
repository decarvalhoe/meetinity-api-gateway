import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import jwt
import pytest
import requests
from urllib3._collections import HTTPHeaderDict


class _CapturingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.app import create_app  # noqa: E402


def _create_app_without_cors_origins(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    monkeypatch.setenv("USER_SERVICE_URL", "http://upstream")
    monkeypatch.setenv("JWT_SECRET", "secret")
    monkeypatch.setenv("RATE_LIMIT_AUTH", "10/minute")
    monkeypatch.setenv("RESILIENCE_BACKOFF_FACTOR", "0")

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
    os.environ["RESILIENCE_BACKOFF_FACTOR"] = "0"

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
    assert response.json["status"] == "ok"
    assert response.json["upstreams"]["user_service"] == "up"


def test_health_upstream_down(client, monkeypatch):
    def fail_health(*args, **kwargs):
        raise requests.RequestException()

    monkeypatch.setattr("src.app.requests.get", fail_health)

    response = client.get("/health")
    assert response.status_code == 503
    assert response.json["status"] == "error"
    assert response.json["upstreams"]["user_service"] == "down"


def test_users_requires_jwt(client):
    response = client.get("/api/users/me")
    assert response.status_code == 401
    assert response.json == {"error": {"code": 401, "message": "Unauthorized"}}


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
    assert response.json == {"error": {"code": 502, "message": "Bad Gateway"}}


def test_proxy_preserves_duplicate_query_params(client, monkeypatch):
    captured = {}

    def fake_request(*args, **kwargs):
        captured["params"] = kwargs.get("params")
        captured["timeout"] = kwargs.get("timeout")
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
    assert captured["timeout"] == (2.0, 10.0)


def test_proxy_preserves_multiple_set_cookie_headers(client, monkeypatch):
    header_dict = HTTPHeaderDict()
    header_dict.add("Set-Cookie", "a=1; Path=/")
    header_dict.add("Set-Cookie", "b=2; Path=/")

    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.content = b"{}"
    mock_resp.raw = Mock(headers=header_dict)
    mock_resp.headers = {}

    monkeypatch.setattr(
        "src.routes.proxy.requests.request", lambda *args, **kwargs: mock_resp
    )

    response = client.get("/api/auth/session")

    assert response.status_code == 200
    assert response.headers.getlist("Set-Cookie") == [
        "a=1; Path=/",
        "b=2; Path=/",
    ]


def test_proxy_generates_request_id_and_forwarded_headers(client, monkeypatch):
    captured = {}

    def fake_request(*args, **kwargs):
        captured["headers"] = kwargs.get("headers")
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b"{}"
        mock_resp.headers = {}
        return mock_resp

    monkeypatch.setattr("src.routes.proxy.requests.request", fake_request)

    response = client.get(
        "/api/auth/session",
        base_url="https://localhost",
        environ_base={"REMOTE_ADDR": "198.51.100.4"},
    )

    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    forwarded_headers = captured["headers"]
    assert forwarded_headers["X-Forwarded-For"] == "198.51.100.4"
    assert forwarded_headers["X-Forwarded-Proto"] == "https"
    assert forwarded_headers["X-Request-ID"] == response.headers["X-Request-ID"]


def test_proxy_appends_forwarded_for_header(client, monkeypatch):
    captured = {}

    def fake_request(*args, **kwargs):
        captured["headers"] = kwargs.get("headers")
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b"{}"
        mock_resp.headers = {}
        return mock_resp

    monkeypatch.setattr("src.routes.proxy.requests.request", fake_request)

    response = client.get(
        "/api/auth/session",
        headers={"X-Forwarded-For": "203.0.113.10"},
        environ_base={"REMOTE_ADDR": "198.51.100.4"},
    )

    assert response.status_code == 200
    forwarded_headers = captured["headers"]
    assert (
        forwarded_headers["X-Forwarded-For"]
        == "203.0.113.10, 198.51.100.4"
    )


def test_request_logging_includes_metadata(client):
    handler = _CapturingHandler()
    handler.setLevel(logging.INFO)
    client.application.logger.addHandler(handler)
    try:
        response = client.get(
            "/health",
            headers={"X-Forwarded-For": "203.0.113.20"},
            environ_base={"REMOTE_ADDR": "198.51.100.4"},
        )
    finally:
        client.application.logger.removeHandler(handler)

    assert response.status_code == 200
    assert handler.records
    payload = json.loads(handler.records[-1].getMessage())
    assert payload["method"] == "GET"
    assert payload["path"] == "/health"
    assert payload["status"] == 200
    assert payload["ip"] == "203.0.113.20"
    assert payload["request_id"] == response.headers["X-Request-ID"]


def test_request_logging_includes_user_id(client, monkeypatch):
    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.content = b"{}"
    mock_resp.headers = {}

    monkeypatch.setattr(
        "src.routes.proxy.requests.request", lambda *args, **kwargs: mock_resp
    )

    handler = _CapturingHandler()
    handler.setLevel(logging.INFO)
    client.application.logger.addHandler(handler)

    token = jwt.encode(
        {
            "sub": "user-123",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            "iat": datetime.now(timezone.utc),
        },
        "secret",
        algorithm="HS256",
    )

    try:
        response = client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        client.application.logger.removeHandler(handler)

    assert response.status_code == 200
    assert handler.records
    payload = json.loads(handler.records[-1].getMessage())
    assert payload["user_id"] == "user-123"


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

