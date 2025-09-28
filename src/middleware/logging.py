"""Request logging middleware for the API gateway."""

import json
import logging
import time
import uuid
from typing import Any, Dict

from flask import Flask, Response, g, request
from opentelemetry import trace


def _serialise_log(record: Dict[str, Any]) -> str:
    """Serialise a dictionary as a JSON string for structured logging."""

    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def setup_request_logging(app: Flask) -> None:
    """Attach request logging hooks to the provided Flask application."""

    logger = logging.getLogger(app.logger.name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    logger.setLevel(app.config.get("LOG_LEVEL", logging.INFO))
    logger.propagate = False
    app.logger = logger

    @app.before_request
    def _start_timer() -> None:  # pragma: no cover - invoked by Flask
        g.request_started_at = time.perf_counter()
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = uuid.uuid4().hex
        g.request_id = request_id

        g.remote_addr = request.remote_addr or ""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = g.remote_addr
        g.client_ip = client_ip

    @app.after_request
    def _log_request(response: Response) -> Response:  # pragma: no cover - invoked by Flask
        start = getattr(g, "request_started_at", None)
        duration_ms = None
        if start is not None:
            duration_ms = (time.perf_counter() - start) * 1000

        log_record: Dict[str, Any] = {
            "method": request.method,
            "path": request.full_path.rstrip("?") or request.path,
            "status": response.status_code,
            "duration_ms": round(duration_ms, 3) if duration_ms is not None else None,
            "ip": getattr(g, "client_ip", request.remote_addr),
            "request_id": getattr(g, "request_id", None),
            "route": getattr(request.url_rule, "rule", request.path),
            "user_agent": request.headers.get("User-Agent"),
            "referer": request.headers.get("Referer"),
            "host": request.host,
        }

        user_id = getattr(g, "jwt_user_id", None)
        if user_id:
            log_record["user_id"] = user_id

        span = trace.get_current_span()
        context = span.get_span_context()
        if context and context.trace_id:
            log_record["trace_id"] = format(context.trace_id, "032x")
        if context and context.span_id:
            log_record["span_id"] = format(context.span_id, "016x")

        app.logger.info(_serialise_log(log_record))

        metrics = app.extensions.get("metrics")
        if metrics:
            duration_seconds = (duration_ms / 1000.0) if duration_ms is not None else None
            metrics.observe_http_request(
                method=request.method,
                endpoint=getattr(request.url_rule, "rule", request.path),
                status=response.status_code,
                duration_seconds=duration_seconds,
            )

        request_id = getattr(g, "request_id", None)
        if request_id:
            response.headers.setdefault("X-Request-ID", request_id)

        return response
