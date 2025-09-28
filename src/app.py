"""Meetinity API Gateway application factory."""
import gzip
import io
import logging
import os
import time
from typing import Any, Callable, Dict, Tuple

import requests
from dotenv import load_dotenv
from flask import Flask, current_app, g, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

try:  # pragma: no cover - optional dependency
    import brotli  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    brotli = None

from requests.adapters import HTTPAdapter

from .middleware.logging import setup_request_logging
from .middleware.resilience import ResilienceMiddleware
from .observability import (
    configure_metrics,
    configure_structured_logging,
    configure_tracing,
)
from .security.api_keys import configure_api_keys
from .security.oauth import DiscoveryError, OIDCProvider
from .security.signatures import configure_request_signatures
from .services.registry import create_service_registry
from .transformations import build_pipeline, load_transformation_rules
from .utils.responses import error_response
from .performance.cache import Cache, InMemoryCacheBackend, RedisCacheBackend, SingleFlight


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


def _parse_mapping(raw: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in raw.split(","):
        key, sep, value = item.partition("=")
        key = key.strip()
        if not key or not sep:
            continue
        mapping[key] = value.strip()
    return mapping


def _normalize_versions(raw: str | None, fallback: tuple[str, ...]) -> tuple[str, ...]:
    values = _split_env_list(raw or "")
    if not values:
        values = list(fallback)
    seen: dict[str, None] = {}
    for item in values:
        if item and item not in seen:
            seen[item] = None
    return tuple(seen.keys()) or fallback


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


def _configure_http_session(app: Flask) -> None:
    """Initialise a pooled HTTP session for upstream calls."""

    pool_connections = int(app.config.get("PROXY_POOL_CONNECTIONS", 10))
    pool_maxsize = int(app.config.get("PROXY_POOL_MAXSIZE", 10))
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if app.config.get("PROXY_SESSION_KEEPALIVE", True):
        session.headers.setdefault("Connection", "keep-alive")
    app.extensions["http_session"] = session
    app.extensions["request_coalescer"] = SingleFlight()


def _configure_cache(app: Flask) -> None:
    """Configure the response cache if enabled."""

    if not app.config.get("CACHE_ENABLED", False):
        return

    backend_name = str(app.config.get("CACHE_BACKEND", "memory")).lower()
    backend: InMemoryCacheBackend | RedisCacheBackend
    if backend_name == "redis":
        redis_url = app.config.get("CACHE_REDIS_URL", "")
        namespace = app.config.get("CACHE_REDIS_NAMESPACE", "api-gateway")
        if redis_url:
            try:
                backend = RedisCacheBackend(redis_url, key_namespace=namespace)
            except Exception as exc:  # pragma: no cover - fallback path
                app.logger.warning(
                    "Redis cache backend unavailable (%s), falling back to in-memory", exc
                )
                backend = InMemoryCacheBackend()
        else:
            app.logger.warning(
                "CACHE_BACKEND is set to redis but CACHE_REDIS_URL is missing; using in-memory cache"
            )
            backend = InMemoryCacheBackend()
    else:
        backend = InMemoryCacheBackend()

    ttl = app.config.get("CACHE_DEFAULT_TTL")
    app.extensions["response_cache"] = Cache(backend, default_ttl=ttl)


_COMPRESSIBLE_MIMETYPES = {
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
    "image/svg+xml",
}


def _parse_accept_encoding(header_value: str) -> list[tuple[str, float]]:
    encodings: list[tuple[str, float]] = []
    for part in header_value.split(","):
        token = part.strip()
        if not token:
            continue
        encoding = token
        q = 1.0
        if ";" in token:
            encoding, *params = [segment.strip() for segment in token.split(";")]
            for param in params:
                if param.startswith("q="):
                    try:
                        q = float(param[2:])
                    except ValueError:
                        q = 0.0
        encodings.append((encoding, q))
    encodings.sort(key=lambda item: item[1], reverse=True)
    return encodings


def _negotiate_encoding(header_value: str, available: tuple[str, ...]) -> str | None:
    for encoding, quality in _parse_accept_encoding(header_value):
        if quality <= 0:
            continue
        encoding = encoding.lower()
        if encoding in available:
            return encoding
        if encoding == "*" and available:
            return available[0]
    return None


def _configure_compression(app: Flask) -> None:
    """Register an ``after_request`` hook that compresses responses."""

    available_encodings: list[str] = []
    if brotli is not None:
        available_encodings.append("br")
    available_encodings.append("gzip")
    available = tuple(available_encodings)

    min_size = int(app.config.get("COMPRESSION_MIN_SIZE", 512))
    gzip_level = int(app.config.get("COMPRESSION_GZIP_LEVEL", 6))
    brotli_quality = int(app.config.get("COMPRESSION_BR_QUALITY", 5))

    def _compress(data: bytes, encoding: str) -> bytes:
        if encoding == "gzip":
            buffer = io.BytesIO()
            with gzip.GzipFile(fileobj=buffer, mode="wb", compresslevel=gzip_level) as gz:
                gz.write(data)
            return buffer.getvalue()
        if encoding == "br" and brotli is not None:
            return brotli.compress(data, quality=brotli_quality)
        raise ValueError(f"Unsupported encoding: {encoding}")

    def _should_compress(response) -> bool:
        if not app.config.get("COMPRESSION_ENABLED", False):
            return False
        if response.direct_passthrough:
            return False
        if request.method == "HEAD":
            return False
        if response.status_code < 200 or response.status_code >= 300:
            return False
        if "Content-Encoding" in response.headers:
            return False

        mimetype = (response.mimetype or "").lower()
        length = response.calculate_content_length()
        if mimetype.startswith("text/") or mimetype in _COMPRESSIBLE_MIMETYPES:
            pass
        else:
            if length is None:
                data = response.get_data()
                if len(data) < min_size:
                    return False
            elif length < min_size:
                return False
            else:
                return False

        if length is not None and length < min_size:
            return False
        if length is None and len(response.get_data()) < min_size:
            return False
        return True

    @app.after_request
    def _compress_response(response):
        if not _should_compress(response):
            return response

        encoding = _negotiate_encoding(request.headers.get("Accept-Encoding", ""), available)
        if not encoding:
            return response

        data = response.get_data()
        try:
            compressed = _compress(data, encoding)
        except ValueError:
            return response

        response.set_data(compressed)
        response.headers["Content-Encoding"] = encoding
        vary_header = response.headers.get("Vary")
        if vary_header:
            vary_values = {value.strip() for value in vary_header.split(",") if value.strip()}
            vary_values.add("Accept-Encoding")
            response.headers["Vary"] = ", ".join(sorted(vary_values))
        else:
            response.headers["Vary"] = "Accept-Encoding"
        response.headers.pop("Content-Length", None)
        return response


HealthResult = Tuple[str, Dict[str, Any], int]


def _check_gateway_health(app: Flask) -> HealthResult:
    return "up", {"logger": app.logger.name}, 200


def _check_user_service_health(app: Flask) -> HealthResult:
    url = app.config.get("USER_SERVICE_URL", "").rstrip("/")
    if not url:
        return "degraded", {"message": "USER_SERVICE_URL not configured"}, 200

    target = f"{url}/health"
    try:
        response = requests.get(target, timeout=(2, 5))
    except requests.RequestException as exc:
        return "down", {"message": str(exc), "target": target}, 503

    if response.status_code == 200:
        return "up", {"target": target, "status_code": response.status_code}, 200

    status = "degraded" if response.status_code < 500 else "down"
    http_status = 200 if status == "degraded" else 503
    return status, {"target": target, "status_code": response.status_code}, http_status


def _check_service_registry_health(app: Flask) -> HealthResult:
    registry = app.extensions.get("service_registry")
    if not registry:
        return "degraded", {"message": "Registry not initialised"}, 200

    service_name = app.config.get("USER_SERVICE_NAME", "user-service")
    try:
        instances = registry.get_instances(service_name, force_refresh=True)
    except Exception as exc:  # pragma: no cover - defensive
        return "down", {"message": str(exc), "service": service_name}, 503

    if not instances:
        return "degraded", {"message": "No instances discovered", "service": service_name}, 200

    return "up", {"instances": [inst.url for inst in instances], "service": service_name}, 200


def _check_oidc_health(app: Flask) -> HealthResult:
    provider = app.extensions.get("oidc_provider")
    if not provider:
        return "skipped", {"message": "OIDC not configured"}, 200

    try:
        metadata = provider.discover(force=True)
    except DiscoveryError as exc:
        return "down", {"message": str(exc)}, 503
    except requests.RequestException as exc:  # pragma: no cover - network issues
        return "down", {"message": str(exc)}, 503

    return "up", {"issuer": metadata.issuer}, 200


def _check_observability_health(app: Flask) -> HealthResult:
    metrics_ready = "metrics" in app.extensions
    tracing_ready = "tracer_provider" in app.extensions
    missing = []
    if not metrics_ready:
        missing.append("metrics")
    if not tracing_ready:
        missing.append("tracing")

    if missing:
        return "degraded", {"missing": missing}, 200

    return "up", {"logger": app.logger.name}, 200


def _register_health_endpoints(app: Flask) -> None:
    checks: Dict[str, Callable[[Flask], HealthResult]] = {
        "gateway": _check_gateway_health,
        "user-service": _check_user_service_health,
        "service-registry": _check_service_registry_health,
        "oidc": _check_oidc_health,
        "observability": _check_observability_health,
    }

    def _execute(check_name: str) -> Tuple[str, Dict[str, Any], int]:
        check = checks.get(check_name)
        if not check:
            return "unknown", {"message": "No such dependency"}, 404
        return check(app)

    @app.route("/health")
    def health():
        dependency_status: Dict[str, Dict[str, Any]] = {}
        overall = "ok"
        http_status = 200

        for name in checks:
            status, details, status_code = _execute(name)
            dependency_status[name] = {"status": status, "details": details}
            if status == "down":
                overall = "error"
                http_status = 503
            elif status not in {"up", "skipped"} and overall == "ok":
                overall = "degraded"
            if status_code >= 500:
                http_status = 503

        payload = {
            "service": "api-gateway",
            "status": overall,
            "dependencies": dependency_status,
        }
        payload["upstreams"] = {
            "user_service": dependency_status.get("user-service", {}).get("status", "unknown")
        }
        return jsonify(payload), http_status

    @app.route("/health/<service>")
    def health_service(service: str):
        status, details, http_status = _execute(service)
        payload = {
            "service": service,
            "status": status,
            "details": details,
        }
        if http_status == 404:
            return jsonify(payload), http_status
        if status == "down" and http_status < 500:
            http_status = 503
        return jsonify(payload), http_status


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
    aggregators_raw = os.getenv("LOG_AGGREGATORS", "")
    app.config["LOG_AGGREGATORS"] = tuple(_split_env_list(aggregators_raw))
    app.config["LOGGER_NAME"] = os.getenv("LOGGER_NAME", "meetinity.api_gateway")


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
    # Performance tuning knobs for the proxy layer. See ``docs/operations/performance.md``
    # for operator guidance on sizing and trade-offs.
    app.config["PROXY_TIMEOUT_CONNECT"] = float(os.getenv("PROXY_TIMEOUT_CONNECT", "2"))
    app.config["PROXY_TIMEOUT_READ"] = float(os.getenv("PROXY_TIMEOUT_READ", "10"))
    app.config["PROXY_POOL_CONNECTIONS"] = int(os.getenv("PROXY_POOL_CONNECTIONS", "10"))
    app.config["PROXY_POOL_MAXSIZE"] = int(os.getenv("PROXY_POOL_MAXSIZE", "10"))
    app.config["PROXY_SESSION_KEEPALIVE"] = _parse_bool(
        os.getenv("PROXY_SESSION_KEEPALIVE"), True
    )
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
    app.config["CACHE_ENABLED"] = _parse_bool(os.getenv("CACHE_ENABLED"), True)
    app.config["CACHE_BACKEND"] = os.getenv("CACHE_BACKEND", "memory")
    app.config["CACHE_DEFAULT_TTL"] = float(os.getenv("CACHE_DEFAULT_TTL", "5"))
    app.config["CACHE_REDIS_URL"] = os.getenv("CACHE_REDIS_URL", "")
    app.config["CACHE_REDIS_NAMESPACE"] = os.getenv("CACHE_REDIS_NAMESPACE", "api-gateway")
    app.config["CACHE_VARY_HEADERS"] = tuple(
        _split_env_list(os.getenv("CACHE_VARY_HEADERS", "Authorization"))
    )
    app.config["COMPRESSION_ENABLED"] = _parse_bool(
        os.getenv("COMPRESSION_ENABLED"), True
    )
    app.config["COMPRESSION_MIN_SIZE"] = int(os.getenv("COMPRESSION_MIN_SIZE", "512"))
    app.config["COMPRESSION_GZIP_LEVEL"] = int(os.getenv("COMPRESSION_GZIP_LEVEL", "6"))
    app.config["COMPRESSION_BR_QUALITY"] = int(os.getenv("COMPRESSION_BR_QUALITY", "5"))

    configured_versions = _normalize_versions(os.getenv("API_VERSIONS"), ("v1", "v2"))
    default_version = os.getenv("API_DEFAULT_VERSION") or (configured_versions[0] if configured_versions else "v1")
    if default_version not in configured_versions:
        configured_versions = (default_version, *[v for v in configured_versions if v != default_version])
    app.config["API_VERSIONS"] = configured_versions
    app.config["API_DEFAULT_VERSION"] = default_version
    app.config["API_VERSION_DEPRECATIONS"] = _parse_mapping(os.getenv("API_VERSION_DEPRECATIONS", ""))
    app.config["API_VERSION_SUNSETS"] = _parse_mapping(os.getenv("API_VERSION_SUNSETS", ""))
    app.config["API_VERSION_DEPRECATION_LINKS"] = _parse_mapping(
        os.getenv("API_VERSION_DEPRECATION_LINKS", "")
    )
    app.config["API_VERSION_WARNINGS"] = _parse_mapping(os.getenv("API_VERSION_WARNINGS", ""))
    app.config["OPENAPI_OUTPUT_PATH"] = os.getenv(
        "OPENAPI_OUTPUT_PATH", os.path.join(os.getcwd(), "docs", "openapi.yaml")
    )

    _configure_logging(app)
    configure_structured_logging(app)
    configure_metrics(app)
    setup_request_logging(app)

    CORS(app, **_cors_configuration())
    limiter.init_app(app)
    try:  # Ensure deterministic limits across test runs.
        with app.app_context():
            limiter.reset()
    except Exception:  # pragma: no cover - defensive; reset may not exist on older versions
        app.logger.debug("Rate limiter reset failed", exc_info=True)
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

    from .management.analytics import AnalyticsCollector

    analytics = AnalyticsCollector()
    app.extensions["analytics"] = analytics

    @app.before_request
    def _start_request_timer():
        g._request_started_at = time.perf_counter()

    @app.after_request
    def _record_request_metrics(response):
        started = getattr(g, "_request_started_at", None)
        duration = time.perf_counter() - started if started is not None else 0.0
        version = getattr(g, "api_version", app.config.get("API_DEFAULT_VERSION"))
        api_key_header = app.config.get("API_KEY_HEADER", "X-API-Key")
        api_key = request.headers.get(api_key_header)
        analytics.record_request(
            endpoint=request.endpoint or request.path,
            method=request.method,
            status_code=response.status_code,
            version=version,
            duration=duration,
            api_key=api_key,
        )
        return response

    from .routes import register_versioned_proxy_blueprints

    register_versioned_proxy_blueprints(app)
    _register_health_endpoints(app)
    configure_tracing(app)
    _configure_http_session(app)
    _configure_cache(app)
    _configure_compression(app)

    from .utils.openapi import generate_openapi_document
    from .routes.docs import create_docs_blueprint
    from .middleware.deprecation import register_deprecation_middleware

    generate_openapi_document(app)
    app.register_blueprint(create_docs_blueprint())
    register_deprecation_middleware(app)

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
