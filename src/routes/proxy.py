"""Proxy routes for the API Gateway."""

from __future__ import annotations

from typing import Dict, Iterable, Tuple

import requests
from flask import Blueprint, Response, current_app, g, request

from ..app import limiter
from ..middleware.jwt import require_jwt
from ..utils.responses import error_response

proxy_bp = Blueprint("proxy", __name__)


def _forward(path: str) -> Response:
    """Forward a request to the upstream user service."""

    base_url = current_app.config.get("USER_SERVICE_URL", "").rstrip("/")
    url = f"{base_url}/{path}" if path else base_url

    headers = _prepare_headers()
    data = request.get_data(cache=False)
    params = list(request.args.items(multi=True))

    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            timeout=(2, 10),
        )
    except requests.RequestException:
        return error_response(502, "Bad Gateway")

    response_headers = _filter_response_headers(resp.headers.items())
    set_cookie_headers = _extract_set_cookie_headers(resp)
    if set_cookie_headers:
        response_headers.extend(("Set-Cookie", value) for value in set_cookie_headers)

    return Response(resp.content, resp.status_code, response_headers)


def _prepare_headers() -> Dict[str, str]:
    """Prepare headers for the proxied request."""

    excluded = {"host", "content-length"}
    headers: Dict[str, str] = {
        key: value for key, value in request.headers if key.lower() not in excluded
    }

    request_id = getattr(g, "request_id", None)
    if request_id:
        headers["X-Request-ID"] = request_id

    forwarded_for = request.headers.get("X-Forwarded-For")
    remote_addr = getattr(g, "remote_addr", request.remote_addr)
    if forwarded_for and remote_addr:
        headers["X-Forwarded-For"] = f"{forwarded_for}, {remote_addr}"
    elif remote_addr:
        headers.setdefault("X-Forwarded-For", remote_addr)

    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    if proto:
        headers["X-Forwarded-Proto"] = proto

    if "X-Request-ID" not in headers:
        fallback_request_id = request.headers.get("X-Request-ID") or getattr(g, "request_id", None)
        if fallback_request_id:
            headers["X-Request-ID"] = fallback_request_id

    return headers


def _filter_response_headers(headers: Iterable[Tuple[str, str]]):
    """Filter headers that should not be sent back to the client."""

    return [
        (key, value)
        for key, value in headers
        if key.lower() != "set-cookie"
    ]


def _extract_set_cookie_headers(resp: requests.Response):
    """Collect ``Set-Cookie`` headers from a ``requests`` response."""

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

    return set_cookie_values


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
