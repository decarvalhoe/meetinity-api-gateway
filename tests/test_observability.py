"""Tests covering observability helpers."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from unittest.mock import Mock

from src import app as app_module
from src.app import create_app
from src.observability import tracing as tracing_module


def _build_response(status: int = 200, body: bytes | None = None):
    import requests

    response = requests.Response()
    response.status_code = status
    response._content = body or b"{}"
    response.headers["Content-Type"] = "application/json"
    response.headers["X-Test"] = "true"
    return response


def _patch_proxy_session(monkeypatch, handler):
    mock_session = Mock()
    mock_session.request = handler
    monkeypatch.setattr("src.routes.proxy._get_http_session", lambda: mock_session)
    return mock_session


def test_metrics_endpoint_records_requests(monkeypatch):
    monkeypatch.setenv("USER_SERVICE_URL", "http://upstream")
    app = create_app()

    client = app.test_client()
    response = client.get("/health/gateway")
    assert response.status_code == 200

    metrics_response = client.get("/metrics")
    assert metrics_response.status_code == 200
    assert metrics_response.mimetype == "text/plain"
    payload = metrics_response.data.decode()

    assert "api_gateway_http_requests_total" in payload
    assert '{method="GET",endpoint="/health/<service>",status="200"}' in payload


def test_proxy_tracing_creates_spans(monkeypatch):
    exporter = InMemorySpanExporter()

    monkeypatch.setenv("USER_SERVICE_URL", "http://upstream")
    monkeypatch.setenv("LOG_AGGREGATORS", "")

    monkeypatch.setattr(app_module, "configure_tracing", lambda app: None)

    app = create_app()

    tracing_module._provider = None
    tracing_module._requests_instrumented = False
    app.config["OTEL_SPAN_EXPORTER"] = exporter
    app.config["OTEL_USE_SIMPLE_PROCESSOR"] = True
    app.extensions.pop("tracing_configured", None)

    tracing_module.configure_tracing(app)
    _patch_proxy_session(monkeypatch, lambda **_: _build_response())

    client = app.test_client()
    resp = client.get("/api/auth")
    assert resp.status_code == 200

    trace.get_tracer_provider().force_flush()
    spans = exporter.get_finished_spans()
    span_names = {span.name for span in spans}
    assert "proxy.forward" in span_names
    forward_span = next(span for span in spans if span.name == "proxy.forward")
    assert forward_span.attributes.get("http.status_code") == 200

