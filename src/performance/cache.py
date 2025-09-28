"""Caching utilities for proxy performance.

This module provides an abstraction that supports both in-memory and Redis
backends with configurable TTLs and targeted invalidation.  It also exposes a
simple *single-flight* helper to deduplicate concurrent lookups so that only
one upstream call is executed per cache key at a time.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Protocol
import pickle
import threading
import time

try:  # pragma: no cover - optional dependency
    import redis  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    redis = None

from concurrent.futures import Future


class CacheBackend(Protocol):
    """Interface for cache backends."""

    def get(self, key: str) -> Any | None:  # pragma: no cover - protocol
        ...

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:  # pragma: no cover - protocol
        ...

    def invalidate(self, keys: Iterable[str] | None = None, prefix: str | None = None) -> None:  # pragma: no cover - protocol
        ...


@dataclass
class _CacheEntry:
    value: Any
    expires_at: float | None


class InMemoryCacheBackend:
    """Thread-safe in-memory cache backend supporting TTL and invalidation."""

    def __init__(self) -> None:
        self._store: Dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            if entry.expires_at is not None and entry.expires_at < time.monotonic():
                self._store.pop(key, None)
                return None
            return entry.value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        expires_at = None
        if ttl is not None:
            expires_at = time.monotonic() + ttl
        with self._lock:
            self._store[key] = _CacheEntry(value=value, expires_at=expires_at)

    def invalidate(self, keys: Iterable[str] | None = None, prefix: str | None = None) -> None:
        with self._lock:
            if keys:
                for key in keys:
                    self._store.pop(key, None)
            if prefix:
                for key in list(self._store.keys()):
                    if key.startswith(prefix):
                        self._store.pop(key, None)


class RedisCacheBackend:
    """Redis cache backend supporting TTL and targeted invalidation."""

    def __init__(self, url: str, *, key_namespace: str = "") -> None:
        if redis is None:  # pragma: no cover - optional dependency
            raise RuntimeError("redis library is not installed")
        self._client = redis.Redis.from_url(url)
        self._namespace = key_namespace.rstrip(":") + ":" if key_namespace else ""

    def _namespaced(self, key: str) -> str:
        return f"{self._namespace}{key}"

    def get(self, key: str) -> Any | None:
        raw = self._client.get(self._namespaced(key))
        if raw is None:
            return None
        return pickle.loads(raw)

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        data = pickle.dumps(value)
        namespaced = self._namespaced(key)
        if ttl is None:
            self._client.set(namespaced, data)
        else:
            self._client.set(namespaced, data, ex=ttl)

    def invalidate(self, keys: Iterable[str] | None = None, prefix: str | None = None) -> None:
        if keys:
            namespaced_keys = [self._namespaced(key) for key in keys]
            if namespaced_keys:
                self._client.delete(*namespaced_keys)
        if prefix:
            pattern = f"{self._namespaced(prefix)}*"
            for batch in self._scan_iter(pattern):
                if batch:
                    self._client.delete(*batch)

    def _scan_iter(self, pattern: str, count: int = 1000):  # pragma: no cover - iterating helper
        cursor = 0
        while True:
            cursor, keys = self._client.scan(cursor=cursor, match=pattern, count=count)
            if keys:
                yield keys
            if cursor == 0:
                break


@dataclass
class _InFlightCall:
    future: Future
    leader: bool


class SingleFlight:
    """Deduplicate concurrent executions for a given key."""

    def __init__(self) -> None:
        self._calls: Dict[str, _InFlightCall] = {}
        self._lock = threading.Lock()

    def execute(self, key: str, func: Callable[[], Any]) -> Any:
        with self._lock:
            call = self._calls.get(key)
            if call is None:
                call = _InFlightCall(future=Future(), leader=True)
                self._calls[key] = call
            else:
                call.leader = False

        if call.leader:
            try:
                result = func()
            except Exception as exc:  # pragma: no cover - propagated to waiters
                call.future.set_exception(exc)
                raise
            else:
                call.future.set_result(result)
            finally:
                with self._lock:
                    self._calls.pop(key, None)
            return result

        return call.future.result()


class Cache:
    """High-level cache wrapper combining backend storage and single-flight."""

    def __init__(self, backend: CacheBackend, *, default_ttl: float | None = None) -> None:
        self._backend = backend
        self._default_ttl = default_ttl
        self._singleflight = SingleFlight()

    @property
    def default_ttl(self) -> float | None:
        return self._default_ttl

    def get(self, key: str) -> Any | None:
        return self._backend.get(key)

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        ttl = self._default_ttl if ttl is None else ttl
        self._backend.set(key, value, ttl)

    def invalidate(self, *keys: str, prefix: str | None = None) -> None:
        key_iterable: Iterable[str] | None = keys if keys else None
        self._backend.invalidate(key_iterable, prefix=prefix)

    def get_or_set(
        self,
        key: str,
        loader: Callable[[], Any],
        *,
        ttl: float | None = None,
        cache_predicate: Callable[[Any], bool] | None = None,
    ) -> tuple[Any, bool]:
        cached = self.get(key)
        if cached is not None:
            return cached, True

        def _load() -> Any:
            result = loader()
            should_cache = result is not None
            if cache_predicate is not None:
                try:
                    should_cache = should_cache and cache_predicate(result)
                except Exception:
                    should_cache = False
            if should_cache:
                effective_ttl = self._default_ttl if ttl is None else ttl
                self._backend.set(key, result, effective_ttl)
            return result

        result = self._singleflight.execute(key, _load)
        return result, False


__all__ = [
    "Cache",
    "CacheBackend",
    "InMemoryCacheBackend",
    "RedisCacheBackend",
    "SingleFlight",
]
