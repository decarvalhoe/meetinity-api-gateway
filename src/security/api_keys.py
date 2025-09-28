"""API key management and validation utilities."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional, Sequence

from flask import Flask, Request, request

from ..utils.responses import error_response


DEFAULT_HASH_ALGORITHM = "sha256"


def _hash_value(value: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """Return the hexadecimal digest for ``value`` using ``algorithm``."""

    hasher = hashlib.new(algorithm)
    hasher.update(value.encode("utf-8"))
    return hasher.hexdigest()


@dataclass(frozen=True)
class StoredAPIKey:
    """Represent an API key stored in the gateway."""

    key_id: str
    hashed_secret: str
    created_at: float


class APIKeyStore:
    """Securely store API keys as salted hashes and validate presented secrets."""

    def __init__(
        self,
        *,
        keys: Optional[Mapping[str, str]] = None,
        salt: str = "",
        algorithm: str = DEFAULT_HASH_ALGORITHM,
    ) -> None:
        self._salt = salt
        self._algorithm = algorithm
        self._keys: Dict[str, StoredAPIKey] = {}
        if keys:
            for key_id, secret in keys.items():
                self.add_key(key_id, secret, hashed=False)

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> "APIKeyStore":
        """Create a key store from environment variables.

        Keys are read from the ``API_KEYS`` variable using the format
        ``<key-id>:<secret>`` separated by commas. Secrets are hashed immediately
        using the configured algorithm.
        """

        env = env or os.environ
        raw_keys = env.get("API_KEYS", "")
        salt = env.get("API_KEY_SALT", "")
        algorithm = env.get("API_KEY_HASH_ALGORITHM", DEFAULT_HASH_ALGORITHM)

        parsed: Dict[str, str] = {}
        for token in _split_csv(raw_keys):
            if ":" not in token:
                continue
            key_id, secret = token.split(":", 1)
            key_id = key_id.strip()
            secret = secret.strip()
            if key_id and secret:
                parsed[key_id] = secret
        return cls(keys=parsed, salt=salt, algorithm=algorithm)

    @property
    def salt(self) -> str:
        return self._salt

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def add_key(self, key_id: str, secret: str, *, hashed: bool = False) -> None:
        """Add a new API key to the store."""

        if not key_id:
            raise ValueError("key_id must not be empty")
        if not secret:
            raise ValueError("secret must not be empty")

        stored_secret = secret if hashed else self._hash_secret(secret)
        self._keys[key_id] = StoredAPIKey(
            key_id=key_id,
            hashed_secret=stored_secret,
            created_at=time.time(),
        )

    def remove_key(self, key_id: str) -> None:
        """Remove an API key from the store if it exists."""

        self._keys.pop(key_id, None)

    def validate(self, provided_secret: str) -> bool:
        """Validate the provided API key secret against stored hashes."""

        if not provided_secret:
            return False
        candidate = self._hash_secret(provided_secret)
        for stored in self._keys.values():
            if hmac.compare_digest(stored.hashed_secret, candidate):
                return True
        return False

    def _hash_secret(self, secret: str) -> str:
        salted = f"{secret}{self._salt}" if self._salt else secret
        return _hash_value(salted, self._algorithm)

    def as_dict(self) -> Dict[str, StoredAPIKey]:
        """Return a shallow copy of stored keys for inspection/testing."""

        return dict(self._keys)


def _split_csv(raw: str) -> Sequence[str]:
    return [token.strip() for token in raw.split(",") if token.strip()]


class APIKeyMiddleware:
    """Flask middleware enforcing API key validation for incoming requests."""

    def __init__(
        self,
        app: Flask,
        store: APIKeyStore,
        *,
        header_name: str = "X-API-Key",
        enabled: bool = True,
        exempt_paths: Optional[Iterable[str]] = None,
    ) -> None:
        self.app = app
        self.store = store
        self.header_name = header_name
        self.enabled = enabled
        self.exempt_paths = tuple(exempt_paths or ("/health",))
        if enabled:
            app.before_request(self._enforce_api_key)

    def _is_exempt(self, req: Request) -> bool:
        path = req.path or "/"
        return any(path.startswith(prefix) for prefix in self.exempt_paths)

    def _enforce_api_key(self):
        if not self.enabled:
            return None
        if self._is_exempt(request):
            return None

        provided = request.headers.get(self.header_name)
        if not provided:
            return error_response(401, "API key required")
        if not self.store.validate(provided):
            return error_response(403, "Invalid API key")
        return None


def configure_api_keys(app: Flask) -> Optional[APIKeyMiddleware]:
    """Configure API key middleware from application configuration."""

    store = APIKeyStore.from_environment(app.config)
    enabled = app.config.get("API_KEY_REQUIRED", bool(store.as_dict()))
    header_name = app.config.get("API_KEY_HEADER", "X-API-Key")
    exempt_paths = app.config.get("API_KEY_EXEMPT_PATHS", ("/health",))

    if not enabled:
        app.logger.info("API key middleware disabled")
        app.extensions["api_key_store"] = store
        return None

    middleware = APIKeyMiddleware(
        app,
        store,
        header_name=header_name,
        enabled=True,
        exempt_paths=exempt_paths,
    )
    app.extensions["api_key_store"] = store
    return middleware
