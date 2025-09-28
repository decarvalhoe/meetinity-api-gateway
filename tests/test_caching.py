from __future__ import annotations

import gzip
from unittest.mock import Mock

import pytest

from src.app import create_app


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("USER_SERVICE_URL", "http://upstream")
    monkeypatch.setenv("JWT_SECRET", "secret")
    monkeypatch.setenv("RATE_LIMIT_AUTH", "10/minute")
    monkeypatch.setenv("RESILIENCE_BACKOFF_FACTOR", "0")
    monkeypatch.setenv("CACHE_DEFAULT_TTL", "60")
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    with app.test_client() as client:
        yield client


def _patch_proxy_session(monkeypatch, handler):
    mock_session = Mock()
    mock_session.request = handler
    monkeypatch.setattr("src.routes.proxy._get_http_session", lambda: mock_session)
    return mock_session


def _build_response(body: bytes, *, status: int = 200, headers: dict[str, str] | None = None):
    response = Mock()
    response.status_code = status
    response.content = body
    response.headers = headers or {"Content-Type": "application/json"}
    response.raw = Mock(headers={})
    return response


def test_cache_hit_and_miss(client, app, monkeypatch):
    calls = []
    responses = [
        _build_response(b"{\"value\": 1}"),
        _build_response(b"{\"value\": 2}"),
    ]

    def fake_request(method, url, **kwargs):
        calls.append(url)
        return responses[len(calls) - 1]

    _patch_proxy_session(monkeypatch, fake_request)

    first = client.get("/api/auth/session")
    second = client.get("/api/auth/session")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.data == second.data
    assert len(calls) == 1


def test_cache_invalidation_triggers_refresh(client, app, monkeypatch):
    calls = []
    payloads = [b"alpha", b"beta"]

    def fake_request(method, url, **kwargs):
        calls.append(url)
        body = payloads[min(len(calls) - 1, len(payloads) - 1)]
        return _build_response(body)

    _patch_proxy_session(monkeypatch, fake_request)

    first = client.get("/api/auth/session")
    assert first.data == b"alpha"
    app.extensions["response_cache"].invalidate(prefix="GET:/api/auth/session")
    second = client.get("/api/auth/session")
    assert second.data == b"beta"
    assert len(calls) == 2


def test_gzip_compression_applied(client, monkeypatch):
    body = b"{" + (b"x" * 2048) + b"}"

    def fake_request(method, url, **kwargs):
        return _build_response(body)

    _patch_proxy_session(monkeypatch, fake_request)

    response = client.get("/api/auth/session", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") == "gzip"
    decompressed = gzip.decompress(response.data)
    assert decompressed == body
