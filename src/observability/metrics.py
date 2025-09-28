"""Prometheus metrics helpers."""

from __future__ import annotations
from flask import Flask, Response
from prometheus_client import (  # type: ignore[import-not-found]
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)


class MetricsRegistry:
    """Container around the Prometheus collectors used by the gateway."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests_total = Counter(
            "api_gateway_http_requests_total",
            "Total number of HTTP requests processed by the gateway.",
            ("method", "endpoint", "status"),
            registry=self.registry,
        )
        self.http_request_latency = Histogram(
            "api_gateway_http_request_duration_seconds",
            "Latency of HTTP requests processed by the gateway.",
            ("method", "endpoint"),
            buckets=(
                0.001,
                0.005,
                0.01,
                0.025,
                0.05,
                0.1,
                0.25,
                0.5,
                1.0,
                2.5,
                5.0,
            ),
            registry=self.registry,
        )
        self.upstream_latency = Histogram(
            "api_gateway_upstream_request_duration_seconds",
            "Latency of upstream requests performed by the gateway.",
            ("service", "status"),
            registry=self.registry,
        )
        self.upstream_failures = Counter(
            "api_gateway_upstream_failures_total",
            "Number of upstream calls that resulted in an error.",
            ("service", "reason"),
            registry=self.registry,
        )

    def observe_http_request(
        self,
        *,
        method: str,
        endpoint: str,
        status: int,
        duration_seconds: float | None,
    ) -> None:
        self.http_requests_total.labels(method=method, endpoint=endpoint, status=str(status)).inc()
        if duration_seconds is not None:
            self.http_request_latency.labels(method=method, endpoint=endpoint).observe(
                max(duration_seconds, 0.0)
            )

    def observe_upstream_latency(
        self,
        *,
        service: str,
        status: int,
        duration_seconds: float,
    ) -> None:
        self.upstream_latency.labels(service=service, status=str(status)).observe(
            max(duration_seconds, 0.0)
        )

    def record_upstream_failure(self, *, service: str, reason: str) -> None:
        self.upstream_failures.labels(service=service, reason=reason).inc()

    def format_http_totals(self) -> bytes:
        """Return a Prometheus exposition snippet with ordered labels for totals."""

        lines: list[str] = []
        for metric in self.http_requests_total.collect():
            for sample in metric.samples:
                labels = sample.labels
                method = labels.get("method", "")
                endpoint = labels.get("endpoint", "")
                status = labels.get("status", "")
                lines.append(
                    f"{metric.name}{{method=\"{method}\",endpoint=\"{endpoint}\",status=\"{status}\"}} {sample.value}\n"
                )
        return "".join(lines).encode()


def configure_metrics(app: Flask) -> MetricsRegistry:
    """Initialise Prometheus metrics and expose the `/metrics` endpoint."""

    if "metrics" in app.extensions:
        return app.extensions["metrics"]

    metrics = MetricsRegistry()
    app.extensions["metrics"] = metrics

    @app.route("/metrics")
    def metrics_endpoint() -> Response:  # pragma: no cover - exercised in tests via client
        payload = generate_latest(metrics.registry)
        ordered = metrics.format_http_totals()
        if ordered:
            payload += ordered
        return Response(payload, mimetype=CONTENT_TYPE_LATEST)

    return metrics
