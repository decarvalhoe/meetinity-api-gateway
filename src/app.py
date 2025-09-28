"""Meetinity API Gateway application factory."""
import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, current_app, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

from .middleware.logging import setup_request_logging
from .middleware.resilience import ResilienceMiddleware
from .security.api_keys import configure_api_keys
from .security.oauth import OIDCProvider
from .security.signatures import configure_request_signatures
from .services.registry import create_service_registry
from .transformations import build_pipeline, load_transformation_rules
from .utils.responses import error_response


def _rate_limit_key_func() -> str:
    header_name = current_app.config.get("API_KEY_HEADER", "X-API-Key")
    api_key = request.headers.get(header_name)
    return api_key or get_remote_address()


limiter = Limiter(key_func=_rate_limit_key_func)


def _split_env_list(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _configure_ip_filters(app: Flask) -> None:
    whitelist = set(app.config.get("IP_WHITELIST", set()))
    blacklist = set(app.config.get("IP_BLACKLIST", set()))

    if not whitelist and not blacklist:
        return

    @app.before_request
    def _enforce_ip_rules():
        remote_ip = request.remote_addr or ""
        if whitelist and remote_ip not in whitelist:
            app.logger.warning("Rejected request from non-whitelisted IP %s", remote_ip)
            return error_response(403, "Forbidden")
        if blacklist and remote_ip in blacklist:
            app.logger.warning("Rejected request from blacklisted IP %s", remote_ip)
            return error_response(403, "Forbidden")
        return None


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

    api_keys_raw = os.getenv("API_KEYS", "")
    signing_secrets_raw = os.getenv("SIGNING_SECRETS", "")
    signature_headers_raw = os.getenv("SIGNATURE_HEADERS", "")
    signature_exempt_raw = os.getenv("SIGNATURE_EXEMPT_PATHS", "/health")
    api_key_exempt_raw = os.getenv("API_KEY_EXEMPT_PATHS", "/health")
    ip_whitelist_raw = os.getenv("IP_WHITELIST", "")
    ip_blacklist_raw = os.getenv("IP_BLACKLIST", "")
    oauth_cache_ttl = int(os.getenv("OAUTH_CACHE_TTL", "300"))

    app.config["USER_SERVICE_URL"] = os.getenv("USER_SERVICE_URL", "")
    app.config["USER_SERVICE_NAME"] = os.getenv("USER_SERVICE_NAME", "user-service")
    app.config["USER_SERVICE_STATIC_INSTANCES"] = os.getenv(
        "USER_SERVICE_STATIC_INSTANCES", ""
    )
    app.config["SERVICE_DISCOVERY_BACKEND"] = os.getenv(
        "SERVICE_DISCOVERY_BACKEND", "static"
    )
    app.config["SERVICE_DISCOVERY_REFRESH_INTERVAL"] = float(
        os.getenv("SERVICE_DISCOVERY_REFRESH_INTERVAL", "30")
    )
    app.config["LOAD_BALANCER_STRATEGY"] = os.getenv(
        "LOAD_BALANCER_STRATEGY", "round_robin"
    )
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "")
    app.config["RATE_LIMIT_AUTH"] = os.getenv("RATE_LIMIT_AUTH", "10/minute")
    app.config["API_KEYS"] = api_keys_raw
    app.config["API_KEY_HEADER"] = os.getenv("API_KEY_HEADER", "X-API-Key")
    app.config["API_KEY_SALT"] = os.getenv("API_KEY_SALT", "")
    app.config["API_KEY_HASH_ALGORITHM"] = os.getenv(
        "API_KEY_HASH_ALGORITHM", "sha256"
    )
    app.config["API_KEY_REQUIRED"] = _parse_bool(
        os.getenv("API_KEY_REQUIRED"), bool(api_keys_raw)
    )
    app.config["API_KEY_EXEMPT_PATHS"] = tuple(_split_env_list(api_key_exempt_raw))
    app.config["SIGNING_SECRETS"] = signing_secrets_raw
    app.config["REQUEST_SIGNATURES_ENABLED"] = _parse_bool(
        os.getenv("REQUEST_SIGNATURES_ENABLED"), bool(signing_secrets_raw)
    )
    app.config["SIGNATURE_HEADER"] = os.getenv("SIGNATURE_HEADER", "X-Signature")
    app.config["SIGNATURE_TIMESTAMP_HEADER"] = os.getenv(
        "SIGNATURE_TIMESTAMP_HEADER", "X-Timestamp"
    )
    app.config["SIGNATURE_KEY_ID_HEADER"] = os.getenv(
        "SIGNATURE_KEY_ID_HEADER", "X-Client-Id"
    )
    app.config["SIGNATURE_CLOCK_TOLERANCE"] = int(
        os.getenv("SIGNATURE_CLOCK_TOLERANCE", "300")
    )
    app.config["SIGNATURE_HEADERS"] = _split_env_list(signature_headers_raw)
    app.config["SIGNATURE_EXEMPT_PATHS"] = tuple(
        _split_env_list(signature_exempt_raw)
    )
    app.config["IP_WHITELIST"] = set(_split_env_list(ip_whitelist_raw))
    app.config["IP_BLACKLIST"] = set(_split_env_list(ip_blacklist_raw))
    app.config["OAUTH_PROVIDER_URL"] = os.getenv("OAUTH_PROVIDER_URL", "")
    app.config["OAUTH_CLIENT_SECRET"] = os.getenv("OAUTH_CLIENT_SECRET", "")
    app.config["OAUTH_AUDIENCE"] = os.getenv("OAUTH_AUDIENCE", "")
    app.config["OAUTH_CACHE_TTL"] = oauth_cache_ttl
    app.config["PROXY_TIMEOUT_CONNECT"] = float(os.getenv("PROXY_TIMEOUT_CONNECT", "2"))
    app.config["PROXY_TIMEOUT_READ"] = float(os.getenv("PROXY_TIMEOUT_READ", "10"))
    app.config["RESILIENCE_MAX_RETRIES"] = int(os.getenv("RESILIENCE_MAX_RETRIES", "2"))
    app.config["RESILIENCE_BACKOFF_FACTOR"] = float(
        os.getenv("RESILIENCE_BACKOFF_FACTOR", "0.5")
    )
    app.config["RESILIENCE_MAX_BACKOFF"] = float(
        os.getenv("RESILIENCE_MAX_BACKOFF", "5")
    )
    app.config["CIRCUIT_BREAKER_FAILURE_THRESHOLD"] = int(
        os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "3")
    )
    app.config["CIRCUIT_BREAKER_RESET_TIMEOUT"] = float(
        os.getenv("CIRCUIT_BREAKER_RESET_TIMEOUT", "30")
    )

    _configure_logging(app)
    setup_request_logging(app)

    CORS(app, **_cors_configuration())
    limiter.init_app(app)
    configure_api_keys(app)
    configure_request_signatures(app)
    _configure_ip_filters(app)

    if app.config["OAUTH_PROVIDER_URL"]:
        app.extensions["oidc_provider"] = OIDCProvider(
            app.config["OAUTH_PROVIDER_URL"], cache_ttl=oauth_cache_ttl
        )

    app.extensions["service_registry"] = create_service_registry(app.config)
    app.extensions["resilience_middleware"] = ResilienceMiddleware(
        failure_threshold=app.config["CIRCUIT_BREAKER_FAILURE_THRESHOLD"],
        recovery_time=app.config["CIRCUIT_BREAKER_RESET_TIMEOUT"],
        max_retries=app.config["RESILIENCE_MAX_RETRIES"],
        backoff_factor=app.config["RESILIENCE_BACKOFF_FACTOR"],
        max_backoff=app.config["RESILIENCE_MAX_BACKOFF"],
    )

    rules_source = os.getenv("TRANSFORMATION_RULES_PATH") or os.getenv(
        "TRANSFORMATION_RULES"
    )
    if rules_source:
        rules = load_transformation_rules(rules_source, base_dir=os.getcwd())
        pipeline = build_pipeline(rules, base_dir=os.getcwd())
        app.extensions["transformation_pipeline"] = pipeline

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
