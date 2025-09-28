"""Tests for security components."""

from __future__ import annotations

import time
from typing import Any, Dict

import jwt
import pytest
from flask import Flask, Request
from werkzeug.test import EnvironBuilder

from src.app import _configure_ip_filters
from src.security.api_keys import APIKeyMiddleware, APIKeyStore
from src.security.oauth import OIDCProvider, ProviderMetadata, TokenValidationError
from src.security.signatures import RequestSignatureMiddleware, RequestSigner


class DummyResponse:
    def __init__(self, status_code: int, payload: Dict[str, Any]):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class DummySession:
    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata
        self.calls: list[str] = []

    def get(self, url: str, timeout: int):  # noqa: D401 - simple stub
        self.calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return DummyResponse(200, self.metadata)
        raise AssertionError(f"Unexpected URL {url}")


def build_request(
    method: str,
    path: str,
    data: bytes | str = b"",
    headers: Dict[str, str] | None = None,
) -> Request:
    builder = EnvironBuilder(method=method, path=path, data=data, headers=headers or {})
    env = builder.get_environ()
    return Request(env)


def test_api_key_middleware_enforces_keys():
    app = Flask(__name__)
    store = APIKeyStore(keys={"client": "topsecret"})
    APIKeyMiddleware(app, store, exempt_paths=())

    @app.route("/protected")
    def protected():
        return "ok"

    client = app.test_client()

    missing = client.get("/protected")
    assert missing.status_code == 401

    invalid = client.get("/protected", headers={"X-API-Key": "wrong"})
    assert invalid.status_code == 403

    valid = client.get("/protected", headers={"X-API-Key": "topsecret"})
    assert valid.status_code == 200


def test_oidc_provider_discovers_and_validates_hs256():
    metadata = {
        "issuer": "https://id.example.com",
        "authorization_endpoint": "https://id.example.com/auth",
        "token_endpoint": "https://id.example.com/token",
        "jwks_uri": "https://id.example.com/jwks",
        "id_token_signing_alg_values_supported": ["HS256"],
    }
    session = DummySession(metadata)
    provider = OIDCProvider(metadata["issuer"], session=session)

    discovered = provider.discover(force=True)
    assert isinstance(discovered, ProviderMetadata)
    assert discovered.issuer == metadata["issuer"]

    now = int(time.time())
    payload = {
        "sub": "123",
        "aud": "api-gateway",
        "iss": metadata["issuer"],
        "exp": now + 300,
        "iat": now,
    }
    token = jwt.encode(payload, "shared-secret", algorithm="HS256")

    validated = provider.validate_token(
        token,
        audience="api-gateway",
        client_secret="shared-secret",
    )
    assert validated["sub"] == "123"

    with pytest.raises(TokenValidationError):
        provider.validate_token(token, audience="api-gateway", client_secret="wrong")


def test_request_signature_middleware_validates_hmac():
    app = Flask(__name__)
    RequestSignatureMiddleware(
        app,
        {"client": "sig-secret"},
        headers_to_include=["X-Test"],
        exempt_paths=(),
    )

    @app.route("/signed", methods=["POST"])
    def signed():
        return "signed"

    timestamp = str(int(time.time()))
    outbound_request = build_request(
        "POST",
        "/signed",
        data=b"payload",
        headers={"X-Test": "value", "X-Client-Id": "client"},
    )
    signer = RequestSigner("sig-secret")
    signature = signer.sign(outbound_request, timestamp=timestamp, headers=["X-Test"])

    client = app.test_client()
    ok = client.post(
        "/signed",
        data=b"payload",
        headers={
            "X-Test": "value",
            "X-Client-Id": "client",
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        },
    )
    assert ok.status_code == 200

    tampered = client.post(
        "/signed",
        data=b"payload",
        headers={
            "X-Test": "value",
            "X-Client-Id": "client",
            "X-Timestamp": timestamp,
            "X-Signature": "bad",
        },
    )
    assert tampered.status_code == 403


def test_ip_filtering_blocks_blacklisted_addresses():
    app = Flask(__name__)
    app.config["IP_WHITELIST"] = {"127.0.0.1"}
    app.config["IP_BLACKLIST"] = {"10.0.0.1"}
    _configure_ip_filters(app)

    @app.route("/ping")
    def ping():
        return "pong"

    client = app.test_client()

    allowed = client.get("/ping")
    assert allowed.status_code == 200

    blocked = client.get("/ping", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
    assert blocked.status_code == 403

    denied = client.get("/ping", environ_overrides={"REMOTE_ADDR": "192.168.0.20"})
    assert denied.status_code == 403
