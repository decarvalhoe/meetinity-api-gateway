"""Request signing utilities for inbound and outbound traffic."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Iterable, Mapping, Optional

from flask import Flask, Request, request

from ..utils.responses import error_response


def _canonical_request(
    req: Request,
    *,
    headers: Optional[Iterable[str]] = None,
    timestamp: str,
) -> bytes:
    body_bytes = req.get_data(cache=True) or b""
    if isinstance(body_bytes, str):
        body_bytes = body_bytes.encode("utf-8")

    hashed_body = hashlib.sha256(body_bytes).hexdigest()
    header_values = []
    if headers:
        for header in headers:
            value = req.headers.get(header, "")
            header_values.append(f"{header.lower()}:{value.strip()}")
    canonical = "\n".join(
        [
            req.method.upper(),
            req.path,
            hashed_body,
            timestamp,
            "\n".join(sorted(header_values)),
        ]
    )
    return canonical.encode("utf-8")


class RequestSigner:
    """Sign outbound requests using shared HMAC secrets."""

    def __init__(self, secret: str, *, algorithm: str = "sha256") -> None:
        self.secret = secret.encode("utf-8")
        self.algorithm = algorithm.lower()

    def sign(
        self,
        req: Request,
        *,
        timestamp: Optional[str] = None,
        headers: Optional[Iterable[str]] = None,
    ) -> str:
        timestamp = timestamp or str(int(time.time()))
        canonical = _canonical_request(req, headers=headers, timestamp=timestamp)
        digest = hmac.new(self.secret, canonical, self.algorithm).digest()
        signature = base64.b64encode(digest).decode("ascii")
        return signature


class RequestSignatureMiddleware:
    """Middleware validating signed requests using HMAC."""

    def __init__(
        self,
        app: Flask,
        secrets: Mapping[str, str],
        *,
        header_signature: str = "X-Signature",
        header_timestamp: str = "X-Timestamp",
        header_key_id: str = "X-Client-Id",
        headers_to_include: Optional[Iterable[str]] = None,
        algorithm: str = "sha256",
        clock_tolerance: int = 300,
        enabled: bool = True,
        exempt_paths: Optional[Iterable[str]] = None,
    ) -> None:
        self.app = app
        self.secrets = {key_id: value.encode("utf-8") for key_id, value in secrets.items()}
        self.header_signature = header_signature
        self.header_timestamp = header_timestamp
        self.header_key_id = header_key_id
        self.headers_to_include = tuple(headers_to_include or ())
        self.algorithm = algorithm.lower()
        self.clock_tolerance = clock_tolerance
        self.enabled = enabled and bool(self.secrets)
        self.exempt_paths = tuple(exempt_paths or ("/health",))
        if self.enabled:
            app.before_request(self._verify_signature)

    def _is_exempt(self, req: Request) -> bool:
        path = req.path or "/"
        return any(path.startswith(prefix) for prefix in self.exempt_paths)

    def _verify_signature(self):
        if not self.enabled:
            return None
        if self._is_exempt(request):
            return None

        key_id = request.headers.get(self.header_key_id)
        signature = request.headers.get(self.header_signature)
        timestamp = request.headers.get(self.header_timestamp)

        if not key_id or not signature or not timestamp:
            return error_response(401, "Signed request headers missing")

        secret = self.secrets.get(key_id)
        if not secret:
            return error_response(403, "Unknown signing key")

        if not self._is_timestamp_valid(timestamp):
            return error_response(401, "Expired signature")

        canonical = _canonical_request(request, headers=self.headers_to_include, timestamp=timestamp)
        expected = base64.b64encode(
            hmac.new(secret, canonical, self.algorithm).digest()
        ).decode("ascii")

        if not hmac.compare_digest(expected, signature):
            return error_response(403, "Invalid signature")

        return None

    def _is_timestamp_valid(self, timestamp: str) -> bool:
        try:
            ts = int(timestamp)
        except ValueError:
            return False
        now = int(time.time())
        return abs(now - ts) <= self.clock_tolerance


def configure_request_signatures(app: Flask) -> Optional[RequestSignatureMiddleware]:
    """Configure request signature verification middleware."""

    secrets_raw = app.config.get("SIGNING_SECRETS", "")
    secrets = {}
    for token in [part.strip() for part in secrets_raw.split(",") if part.strip()]:
        if ":" not in token:
            continue
        key_id, secret = token.split(":", 1)
        if key_id and secret:
            secrets[key_id.strip()] = secret.strip()

    enabled = app.config.get("REQUEST_SIGNATURES_ENABLED", bool(secrets))
    header_signature = app.config.get("SIGNATURE_HEADER", "X-Signature")
    header_timestamp = app.config.get("SIGNATURE_TIMESTAMP_HEADER", "X-Timestamp")
    header_key_id = app.config.get("SIGNATURE_KEY_ID_HEADER", "X-Client-Id")
    algorithm = app.config.get("SIGNATURE_ALGORITHM", "sha256")
    clock_tolerance = int(app.config.get("SIGNATURE_CLOCK_TOLERANCE", 300))
    headers_to_include = app.config.get("SIGNATURE_HEADERS", [])
    exempt_paths = app.config.get("SIGNATURE_EXEMPT_PATHS", ("/health",))

    if not enabled or not secrets:
        app.logger.info("Request signature middleware disabled")
        return None

    middleware = RequestSignatureMiddleware(
        app,
        secrets,
        header_signature=header_signature,
        header_timestamp=header_timestamp,
        header_key_id=header_key_id,
        headers_to_include=headers_to_include,
        algorithm=algorithm,
        clock_tolerance=clock_tolerance,
        exempt_paths=exempt_paths,
    )
    app.extensions["request_signature_middleware"] = middleware
    return middleware
