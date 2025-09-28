"""Meetinity API Gateway application factory."""
import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

from .middleware.logging import setup_request_logging
from .utils.responses import error_response

limiter = Limiter(key_func=get_remote_address)


def _configure_logging(app: Flask) -> None:
    """Configure the Flask application logger.

    The application shares a logger configured by ``setup_request_logging`` so this
    helper simply applies the configured log level.
    """

    level = os.getenv("LOG_LEVEL", "INFO").upper()
    try:
        logging_level = getattr(logging, level)
    except AttributeError:
        logging_level = logging.INFO
    app.config["LOG_LEVEL"] = logging_level
    app.logger.setLevel(logging_level)


def _cors_configuration() -> dict[str, Any]:
    """Build the CORS configuration for the application."""

    origins_env = os.getenv("CORS_ORIGINS")
    origins = []
    if origins_env:
        origins = [origin.strip() for origin in origins_env.split(",") if origin.strip()]

    cors_origins: Any = origins if origins else "*"
    return {
        "origins": cors_origins,
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type", "X-Request-ID"],
        "expose_headers": ["X-Request-ID"],
        "supports_credentials": False,
    }


def create_app() -> Flask:
    """Create and configure the Flask application."""

    load_dotenv()
    app = Flask(__name__)

    app.config["USER_SERVICE_URL"] = os.getenv("USER_SERVICE_URL", "")
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "")
    app.config["RATE_LIMIT_AUTH"] = os.getenv("RATE_LIMIT_AUTH", "10/minute")

    _configure_logging(app)
    setup_request_logging(app)

    CORS(app, **_cors_configuration())
    limiter.init_app(app)

    from .routes.proxy import proxy_bp

    app.register_blueprint(proxy_bp)

    @app.route("/health")
    def health():
        """Return the current health status for the API gateway and upstream."""

        upstream_status = "down"
        overall_status = "error"
        http_status = 503

        url = app.config["USER_SERVICE_URL"].rstrip("/")
        if url:
            try:
                resp = requests.get(f"{url}/health", timeout=(2, 5))
            except requests.RequestException:
                resp = None
            if resp and resp.status_code == 200:
                upstream_status = "up"
                overall_status = "ok"
                http_status = 200

        return jsonify(
            {
                "status": overall_status,
                "service": "api-gateway",
                "upstreams": {"user_service": upstream_status},
            }
        ), http_status

    @app.errorhandler(429)
    def ratelimit_handler(_error):
        """Handle rate limit exceeded errors with a consistent envelope."""

        return error_response(429, "Too Many Requests")

    @app.errorhandler(HTTPException)
    def http_error_handler(error: HTTPException):
        """Return JSON envelopes for Werkzeug HTTP exceptions."""

        status_code = error.code or 500
        message = error.description or error.name or "Error"
        return error_response(status_code, message)

    @app.errorhandler(Exception)
    def generic_error_handler(error: Exception):  # noqa: D401 - brief message sufficient
        """Return a JSON envelope for unexpected errors."""

        app.logger.exception("Unhandled exception", exc_info=error)
        return error_response(500, "Internal Server Error")

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(port=int(os.getenv("APP_PORT", 5000)))
