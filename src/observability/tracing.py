"""OpenTelemetry tracing configuration."""

from __future__ import annotations

from typing import Dict, Iterable

from flask import Flask
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore[import-not-found]
    OTLPSpanExporter,
)
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)


_provider: TracerProvider | None = None
_requests_instrumented = False
_configured_exporters: set[tuple] = set()


def _parse_headers(raw: str | Iterable[str] | None) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if raw is None:
        return headers
    if isinstance(raw, str):
        items = [item.strip() for item in raw.split(",") if item.strip()]
    else:
        items = list(raw)
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        headers[key.strip()] = value.strip()
    return headers


def _build_exporter(app: Flask) -> SpanExporter:
    if exporter := app.config.get("OTEL_SPAN_EXPORTER"):
        return exporter

    exporter_name = str(app.config.get("OTEL_EXPORTER", "otlp")).lower()
    if exporter_name in {"jaeger", "zipkin"}:
        exporter_name = "otlp"
    if exporter_name == "console":
        return ConsoleSpanExporter()

    endpoint = app.config.get("OTEL_EXPORTER_OTLP_ENDPOINT") or app.config.get(
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
    )
    headers = _parse_headers(app.config.get("OTEL_EXPORTER_OTLP_HEADERS"))

    try:
        if endpoint or headers:
            return OTLPSpanExporter(endpoint=endpoint, headers=headers or None)
        # No explicit endpoint configured: fall back to console exporter to avoid network errors.
        return ConsoleSpanExporter()
    except Exception:  # pragma: no cover - defensive
        return ConsoleSpanExporter()


def _exporter_signature(exporter: SpanExporter) -> tuple:
    return (
        exporter.__class__,
        getattr(exporter, "endpoint", None),
        getattr(exporter, "_endpoint", None),
        getattr(exporter, "_collector_endpoint", None),
    )


def configure_tracing(app: Flask) -> TracerProvider:
    """Configure OpenTelemetry tracing for the Flask application."""

    global _provider, _requests_instrumented

    if app.extensions.get("tracing_configured"):
        return trace.get_tracer_provider()  # type: ignore[return-value]

    service_name = app.config.get("OTEL_SERVICE_NAME") or app.import_name
    resource = Resource.create({"service.name": service_name, "service.namespace": "meetinity"})

    if _provider is None:
        existing_provider = trace.get_tracer_provider()
        if isinstance(existing_provider, TracerProvider):
            provider = existing_provider
        else:
            provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(provider)
        _provider = provider
    else:
        provider = _provider

    exporter = _build_exporter(app)
    use_simple = bool(app.config.get("OTEL_USE_SIMPLE_PROCESSOR")) or isinstance(
        exporter, ConsoleSpanExporter
    )
    processor_class = SimpleSpanProcessor if use_simple else BatchSpanProcessor
    signature = _exporter_signature(exporter)
    force_attach = bool(app.config.get("OTEL_SPAN_EXPORTER"))
    if force_attach or signature not in _configured_exporters:
        provider.add_span_processor(processor_class(exporter))
        if not force_attach:
            _configured_exporters.add(signature)

    if not _requests_instrumented:
        RequestsInstrumentor().instrument(raise_on_double_instrumentation=False)
        _requests_instrumented = True

    if not app.extensions.get("otel_flask_instrumented"):
        FlaskInstrumentor().instrument_app(
            app,
            excluded_urls=r"/health[\w/]*|/metrics",
        )
        app.extensions["otel_flask_instrumented"] = True
    app.extensions["tracing_configured"] = True
    app.extensions["tracer_provider"] = provider
    return provider
