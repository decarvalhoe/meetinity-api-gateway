import os
import sys
import pytest
import requests
from unittest.mock import Mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.app import create_app  # noqa: E402


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


def test_auth_proxy_failure(client, monkeypatch):
    def fail_request(*args, **kwargs):
        raise requests.RequestException()
    monkeypatch.setattr(
        "src.routes.proxy.requests.request", fail_request
    )
    response = client.post("/api/auth/login")
    assert response.status_code == 502
