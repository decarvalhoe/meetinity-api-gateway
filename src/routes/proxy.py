from flask import Blueprint, request, Response, jsonify, current_app
import requests
from ..app import limiter
from ..middleware.jwt import require_jwt

proxy_bp = Blueprint("proxy", __name__)


def _forward(path):
    base_url = current_app.config.get("USER_SERVICE_URL", "").rstrip("/")
    url = f"{base_url}/{path}" if path else base_url
    headers = {k: v for k, v in request.headers if k.lower() != "host"}
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            timeout=5,
        )
    except requests.RequestException:
        return jsonify({"error": "Bad gateway"}), 502
    return Response(resp.content, resp.status_code, resp.headers.items())


@proxy_bp.route(
    "/api/auth",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@proxy_bp.route(
    "/api/auth/<path:path>",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT_AUTH", "10/minute"))
def proxy_auth(path):
    return _forward(f"auth/{path}" if path else "auth")


@proxy_bp.route(
    "/api/users",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@proxy_bp.route(
    "/api/users/<path:path>",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@require_jwt
def proxy_users(path):
    return _forward(f"users/{path}" if path else "users")


@proxy_bp.route(
    "/api/profile",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@proxy_bp.route(
    "/api/profile/<path:path>",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@require_jwt
def proxy_profile(path):
    return _forward(f"profile/{path}" if path else "profile")
