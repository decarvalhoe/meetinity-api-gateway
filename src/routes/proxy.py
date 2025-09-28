"""Proxy routes for the API Gateway.

This module handles request forwarding to upstream services,
including authentication middleware and rate limiting.
"""

from flask import Blueprint, request, Response, jsonify, current_app
import requests
from ..app import limiter
from ..middleware.jwt import require_jwt

proxy_bp = Blueprint("proxy", __name__)


def _forward(path):
    """Forward a request to the upstream user service.
    
    Args:
        path (str): The path to append to the service URL.
        
    Returns:
        Response: The response from the upstream service or error response.
    """
    base_url = current_app.config.get("USER_SERVICE_URL", "").rstrip("/")
    url = f"{base_url}/{path}" if path else base_url
    headers = {k: v for k, v in request.headers if k.lower() != "host"}
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            params=list(request.args.items(multi=True)),
            data=request.get_data(),
            timeout=5,
        )
    except requests.RequestException:
        return jsonify({"error": "Bad gateway"}), 502

    response_headers = [
        (key, value)
        for key, value in resp.headers.items()
        if key.lower() != "set-cookie"
    ]

    raw_headers = getattr(getattr(resp, "raw", None), "headers", None)
    set_cookie_values = None

    if raw_headers is not None:
        for accessor in ("get_all", "getlist"):
            getter = getattr(raw_headers, accessor, None)
            if callable(getter):
                try:
                    values = getter("Set-Cookie")
                except TypeError:
                    continue
                if values:
                    if isinstance(values, (list, tuple)):
                        set_cookie_values = list(values)
                    else:
                        set_cookie_values = [values]
                    break

        if set_cookie_values:
            set_cookie_values = [
                value for value in set_cookie_values if isinstance(value, (str, bytes))
            ]
            if not set_cookie_values:
                set_cookie_values = None

        if set_cookie_values is None:
            try:
                values = [
                    value
                    for header, value in raw_headers.items()
                    if header.lower() == "set-cookie"
                ]
            except (TypeError, AttributeError):
                values = None
            if values:
                filtered_values = [
                    value for value in values if isinstance(value, (str, bytes))
                ]
                set_cookie_values = filtered_values or None

    if set_cookie_values is None and "Set-Cookie" in resp.headers:
        set_cookie_values = [resp.headers.get("Set-Cookie")]

    if set_cookie_values:
        response_headers.extend(("Set-Cookie", value) for value in set_cookie_values)

    return Response(resp.content, resp.status_code, response_headers)


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
    """Proxy authentication requests to the user service.
    
    This endpoint forwards authentication-related requests to the user service
    with rate limiting applied to prevent abuse.
    
    Args:
        path (str): The authentication path to forward.
        
    Returns:
        Response: The response from the user service.
    """
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
    """Proxy user management requests to the user service.
    
    This endpoint forwards user-related requests to the user service
    with JWT authentication required.
    
    Args:
        path (str): The user management path to forward.
        
    Returns:
        Response: The response from the user service.
    """
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
    """Proxy profile management requests to the user service.
    
    This endpoint forwards profile-related requests to the user service
    with JWT authentication required.
    
    Args:
        path (str): The profile management path to forward.
        
    Returns:
        Response: The response from the user service.
    """
    return _forward(f"profile/{path}" if path else "profile")
