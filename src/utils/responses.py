"""Utilities for building JSON API responses."""

from typing import Any, Dict, Optional

from flask import jsonify


def error_response(status_code: int, message: str, details: Optional[Dict[str, Any]] = None):
    """Return a JSON error envelope with the provided status code and message."""

    payload: Dict[str, Any] = {"error": {"code": status_code, "message": message}}
    if details:
        payload["error"]["details"] = details
    response = jsonify(payload)
    response.status_code = status_code
    return response
