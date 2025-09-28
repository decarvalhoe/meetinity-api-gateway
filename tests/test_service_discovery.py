from __future__ import annotations
from typing import List
from unittest.mock import Mock

import pytest
import requests

from src.app import create_app
from src.middleware.resilience import ResilienceMiddleware
from src.services.registry import (
    ServiceInstance,
    ServiceRegistry,
    StaticRegistryBackend,
)


def _patch_proxy_session(monkeypatch, handler):
    mock_session = Mock()
    mock_session.request = handler
    monkeypatch.setattr("src.routes.proxy._get_http_session", lambda: mock_session)
    return mock_session


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch):
    monkeypatch.setenv("USER_SERVICE_URL", "http://upstream")
    monkeypatch.setenv("USER_SERVICE_NAME", "user-service")
    monkeypatch.setenv("SERVICE_DISCOVERY_BACKEND", "static")
    monkeypatch.setenv("SERVICE_DISCOVERY_REFRESH_INTERVAL", "0")
    monkeypatch.setenv("RESILIENCE_BACKOFF_FACTOR", "0")
    monkeypatch.setenv("RESILIENCE_MAX_RETRIES", "1")
    monkeypatch.setenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "2")
    monkeypatch.setenv("CIRCUIT_BREAKER_RESET_TIMEOUT", "60")
    yield


def _make_registry(instances: List[ServiceInstance]) -> ServiceRegistry:
    backend = StaticRegistryBackend({instances[0].service_name: instances})
    return ServiceRegistry(backend, refresh_interval=0)


def test_round_robin_strategy_cycles_instances():
    registry = _make_registry(
        [
            ServiceInstance("user-service", "http://a"),
            ServiceInstance("user-service", "http://b"),
        ]
    )

    first = registry.select_instance("user-service", "round_robin")
    second = registry.select_instance("user-service", "round_robin")
    third = registry.select_instance("user-service", "round_robin")

    assert [inst.url for inst in (first, second, third)] == [
        "http://a",
        "http://b",
        "http://a",
    ]


def test_health_strategy_prefers_healthy_instances():
    instances = [
        ServiceInstance("user-service", "http://a", healthy=False),
        ServiceInstance("user-service", "http://b", healthy=True),
    ]
    registry = _make_registry(instances)

    selected = registry.select_instance("user-service", "health")
    assert selected.url == "http://b"


def test_weighted_strategy_repeats_instances_by_weight():
    registry = _make_registry(
        [
            ServiceInstance("user-service", "http://a", weight=2),
            ServiceInstance("user-service", "http://b", weight=1),
        ]
    )

    sequence = [registry.select_instance("user-service", "weighted").url for _ in range(3)]
    assert sequence.count("http://a") == 2
    assert sequence.count("http://b") == 1


def test_proxy_failover_between_instances(monkeypatch):
    monkeypatch.setenv(
        "USER_SERVICE_STATIC_INSTANCES", "http://svc-a,http://svc-b"
    )
    app = create_app()
    app.config["TESTING"] = True
    middleware: ResilienceMiddleware = app.extensions["resilience_middleware"]
    middleware.backoff_factor = 0

    calls: list[str] = []

    def fake_request(method, url, **kwargs):
        calls.append(url)
        if "svc-a" in url:
            raise requests.RequestException("boom")
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b"{}"
        mock_resp.headers = {}
        mock_resp.raw = Mock(headers={})
        return mock_resp

    _patch_proxy_session(monkeypatch, fake_request)

    with app.test_client() as client:
        response = client.get("/api/auth/session")

    assert response.status_code == 200
    assert len(calls) == 2
    assert any("svc-a" in url for url in calls)
    assert any("svc-b" in url for url in calls)


def test_circuit_breaker_opens_after_failures(monkeypatch):
    monkeypatch.setenv("USER_SERVICE_STATIC_INSTANCES", "http://svc-a")
    monkeypatch.setenv("RESILIENCE_MAX_RETRIES", "0")

    app = create_app()
    app.config["TESTING"] = True
    middleware: ResilienceMiddleware = app.extensions["resilience_middleware"]

    current_time = [0.0]

    def fake_time():
        return current_time[0]

    middleware._time_func = fake_time  # type: ignore[attr-defined]
    middleware.backoff_factor = 0

    calls = 0

    def failing_request(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise requests.RequestException("down")

    _patch_proxy_session(monkeypatch, failing_request)

    with app.test_client() as client:
        first = client.get("/api/auth/session")
        second = client.get("/api/auth/session")
        current_time[0] += 10
        third = client.get("/api/auth/session")

    assert first.status_code == 502
    assert second.status_code == 502
    assert third.status_code == 503
    assert calls == 2
