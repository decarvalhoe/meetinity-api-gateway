import os
from functools import wraps
from typing import Any, Callable, Optional

import jwt
from flask import current_app, g, request

from ..utils.responses import error_response


def _decode_jwt(token: str, secret: str) -> Optional[dict[str, Any]]:
    """Decode a JWT using the configured secret."""

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat"]},
        )
    except jwt.PyJWTError:
        return None
    if not payload.get("sub"):
        return None
    return payload


def require_jwt(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Ensure the wrapped endpoint is accessed with a valid JWT."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return current_app.make_default_options_response()

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return error_response(401, "Unauthorized")

        token = auth_header.split(" ", 1)[1]
        secret = current_app.config.get("JWT_SECRET", os.getenv("JWT_SECRET", ""))
        payload = _decode_jwt(token, secret)
        if payload is None:
            return error_response(401, "Unauthorized")

        g.jwt_user_id = payload["sub"]
        g.jwt_payload = payload
        return fn(*args, **kwargs)

    return wrapper
