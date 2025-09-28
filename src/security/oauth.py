"""OAuth 2.0 and OpenID Connect utilities."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional

import jwt
import requests
from jwt import InvalidTokenError, PyJWTError


class DiscoveryError(RuntimeError):
    """Raised when metadata discovery fails."""


class TokenValidationError(RuntimeError):
    """Raised when a token cannot be validated."""


@dataclass
class ProviderMetadata:
    """Container for OpenID Connect discovery metadata."""

    issuer: str
    authorization_endpoint: Optional[str]
    token_endpoint: Optional[str]
    jwks_uri: Optional[str]
    introspection_endpoint: Optional[str]
    userinfo_endpoint: Optional[str]
    algorithms: Iterable[str]


class OIDCProvider:
    """Interact with an OpenID Connect provider."""

    def __init__(
        self,
        issuer: str,
        *,
        session: Optional[requests.Session] = None,
        cache_ttl: int = 300,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self._session = session or requests.Session()
        self._cache_ttl = cache_ttl
        self._metadata: Optional[ProviderMetadata] = None
        self._metadata_expires_at = 0.0
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._jwks_expires_at = 0.0

    def discover(self, *, force: bool = False) -> ProviderMetadata:
        """Fetch the provider metadata using the discovery document."""

        if not force and self._metadata and time.time() < self._metadata_expires_at:
            return self._metadata

        url = f"{self.issuer}/.well-known/openid-configuration"
        response = self._session.get(url, timeout=5)
        if response.status_code != 200:
            raise DiscoveryError(f"Discovery failed with status {response.status_code}")

        payload = response.json()
        metadata = ProviderMetadata(
            issuer=payload.get("issuer", self.issuer),
            authorization_endpoint=payload.get("authorization_endpoint"),
            token_endpoint=payload.get("token_endpoint"),
            jwks_uri=payload.get("jwks_uri"),
            introspection_endpoint=payload.get("introspection_endpoint"),
            userinfo_endpoint=payload.get("userinfo_endpoint"),
            algorithms=payload.get("id_token_signing_alg_values_supported", []),
        )
        self._metadata = metadata
        self._metadata_expires_at = time.time() + self._cache_ttl
        return metadata

    def metadata(self) -> ProviderMetadata:
        """Return cached metadata, performing discovery if needed."""

        return self.discover()

    def _get_jwks(self, *, force: bool = False) -> Dict[str, Any]:
        metadata = self.metadata()
        if not metadata.jwks_uri:
            raise DiscoveryError("Provider metadata does not expose a jwks_uri")

        if not force and self._jwks_cache and time.time() < self._jwks_expires_at:
            return self._jwks_cache

        response = self._session.get(metadata.jwks_uri, timeout=5)
        if response.status_code != 200:
            raise DiscoveryError("Failed to fetch JWKS")
        data = response.json()
        self._jwks_cache = data
        self._jwks_expires_at = time.time() + self._cache_ttl
        return data

    def validate_token(
        self,
        token: str,
        *,
        audience: Optional[str] = None,
        leeway: int = 0,
        client_secret: Optional[str] = None,
        require_signature: bool = True,
    ) -> Dict[str, Any]:
        """Validate an ID/access token against provider metadata."""

        metadata = self.metadata()
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        options = {"require": ["exp", "iat"], "verify_aud": audience is not None}

        try:
            if algorithm and algorithm.startswith("HS"):
                if not client_secret:
                    raise TokenValidationError("client_secret required for HMAC tokens")
                payload = jwt.decode(
                    token,
                    client_secret,
                    algorithms=[algorithm] if algorithm else None,
                    audience=audience,
                    issuer=metadata.issuer,
                    leeway=leeway,
                    options=options,
                )
            else:
                key = self._resolve_jwk_for_token(header)
                if not require_signature and not key:
                    decode_options = {"verify_signature": False, **options}
                    payload = jwt.decode(
                        token,
                        None,
                        audience=audience,
                        issuer=metadata.issuer,
                        leeway=leeway,
                        options=decode_options,
                    )
                elif not key:
                    raise TokenValidationError("Unable to resolve signing key for token")
                else:
                    public_key = _jwk_to_public_key(key)
                    payload = jwt.decode(
                        token,
                        public_key,
                        algorithms=[algorithm] if algorithm else None,
                        audience=audience,
                        issuer=metadata.issuer,
                        leeway=leeway,
                        options=options,
                    )
        except (InvalidTokenError, PyJWTError) as exc:
            raise TokenValidationError(str(exc)) from exc

        return payload

    def _resolve_jwk_for_token(self, header: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
        jwks = self._get_jwks()
        keys = jwks.get("keys", []) if isinstance(jwks, Mapping) else []
        kid = header.get("kid")
        alg = header.get("alg")

        for jwk in keys:
            if kid and jwk.get("kid") != kid:
                continue
            if alg and jwk.get("alg") not in (None, alg):
                continue
            return jwk
        return None


def _jwk_to_public_key(jwk_dict: Mapping[str, Any]):
    """Convert a JWK dictionary into a public key object for PyJWT."""

    try:
        from jwt.algorithms import RSAAlgorithm
    except ImportError as exc:  # pragma: no cover - depends on optional dependency
        raise TokenValidationError("RSA validation requires cryptography support") from exc

    return RSAAlgorithm.from_jwk(json.dumps(jwk_dict))
