"""Structured logging configuration for the API gateway."""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from logging import Handler, Logger
from logging.handlers import DatagramHandler, HTTPHandler, SocketHandler
from typing import Iterable, Mapping
from urllib.parse import urlparse

from flask import Flask


_DEFAULT_LOGGER_NAME = "meetinity.api_gateway"


class JsonFormatter(logging.Formatter):
    """A JSON formatter suited for structured logging."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401 - obvious
        payload: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if hasattr(record, "request_id") and record.request_id:
            payload["request_id"] = record.request_id

        trace_id = getattr(record, "trace_id", None)
        span_id = getattr(record, "span_id", None)
        if trace_id:
            payload["trace_id"] = trace_id
        if span_id:
            payload["span_id"] = span_id

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        for key, value in record.__dict__.items():
            if key in {
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
            }:
                continue
            if key in payload:
                continue
            if key.startswith("_"):
                continue
            payload[key] = value

        return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _create_network_handler(url: str) -> Handler:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Invalid handler URL: {url}")

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme in {"tcp", "socket"}:
        handler = SocketHandler(host, port)
        handler.closeOnError = True  # type: ignore[attr-defined]
        return handler
    if parsed.scheme in {"udp", "datagram"}:
        return DatagramHandler(host, port)
    if parsed.scheme in {"http", "https"}:
        secure = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return HTTPHandler(
            host=f"{host}:{port}",
            url=path,
            method="POST",
            secure=secure,
        )
    raise ValueError(f"Unsupported handler scheme: {parsed.scheme}")


def _normalise_aggregators(raw: Iterable[str] | None) -> list[str]:
    aggregators: list[str] = []
    if not raw:
        return aggregators
    for item in raw:
        item = item.strip()
        if item:
            aggregators.append(item)
    return aggregators


def configure_structured_logging(app: Flask) -> Logger:
    """Configure structured logging for the given Flask application."""

    logger_name = app.config.get("LOGGER_NAME", _DEFAULT_LOGGER_NAME)
    logger = logging.getLogger(logger_name)

    if not logger.handlers:
        logger.setLevel(app.config.get("LOG_LEVEL", logging.INFO))
    logger.handlers = []

    stream_handler = logging.StreamHandler()
    formatter = JsonFormatter()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    aggregators = _normalise_aggregators(app.config.get("LOG_AGGREGATORS"))
    fallback_logger = logging.getLogger(__name__)
    for aggregator in aggregators:
        try:
            handler = _create_network_handler(aggregator)
        except (OSError, ValueError, socket.error) as exc:
            fallback_logger.warning(
                "Failed to configure log aggregator %s: %s", aggregator, exc
            )
            continue
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.propagate = False
    app.logger = logger
    return logger


def enrich_log_record(record: Mapping[str, object]) -> Mapping[str, object]:
    """Return an enriched copy of the log record."""

    enriched = dict(record)
    environment = record.get("environment") or "production"
    enriched.setdefault("environment", environment)
    enriched.setdefault("component", "api-gateway")
    return enriched
