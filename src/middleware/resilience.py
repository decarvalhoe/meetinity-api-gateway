"""Resilience middleware providing retries and circuit breaking."""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Sequence

from ..services.registry import ServiceInstance, ServiceRegistry


class ResilienceError(Exception):
    """Base error raised by the resilience middleware."""


class ServiceUnavailableError(ResilienceError):
    """Raised when no upstream instances are available."""


class UpstreamServiceError(ResilienceError):
    """Raised when upstream calls fail after exhausting retries."""

    def __init__(self, message: str, *, response=None) -> None:
        super().__init__(message)
        self.response = response


class UpstreamRequestError(Exception):
    """Internal wrapper for upstream request failures."""


@dataclass
class _CircuitBreakerState:
    failures: int = 0
    opened_at: float | None = None
    half_open: bool = False


class ResilienceMiddleware:
    """Apply retry, exponential backoff and circuit breaking logic."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        recovery_time: float = 30.0,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        max_backoff: float = 5.0,
        time_func: Callable[[], float] | None = None,
        sleep_func: Callable[[float], None] | None = None,
    ) -> None:
        self.failure_threshold = max(failure_threshold, 1)
        self.recovery_time = max(recovery_time, 0.0)
        self.max_retries = max(max_retries, 0)
        self.backoff_factor = max(backoff_factor, 0.0)
        self.max_backoff = max(max_backoff, 0.0)
        self._time_func = time_func or time.monotonic
        self._sleep_func = sleep_func or time.sleep
        self._lock = threading.Lock()
        self._circuits: Dict[str, _CircuitBreakerState] = {}

    def execute(
        self,
        *,
        registry: ServiceRegistry,
        service_name: str,
        strategy_name: str,
        request_func: Callable[[ServiceInstance], object],
    ):
        """Execute a request against the registry using failover semantics."""

        excluded: set[str] = set()
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            force_refresh = attempt > 0
            instances = registry.get_instances(service_name, force_refresh=force_refresh)
            candidates = self._filter_instances(instances, excluded)
            if not candidates:
                candidates = self._filter_instances(instances, set())
            if not candidates:
                raise ServiceUnavailableError(f"No available instances for {service_name}")

            try:
                instance = registry.select_instance(
                    service_name,
                    strategy_name,
                    instances=candidates,
                )
            except (LookupError, ValueError):
                raise ServiceUnavailableError(f"No available instances for {service_name}")

            try:
                response = request_func(instance)
            except UpstreamRequestError as exc:
                last_error = exc
                self._record_failure(instance)
                excluded.add(instance.identity)
                if attempt < self.max_retries:
                    self._sleep(attempt)
                    continue
                raise UpstreamServiceError("Upstream request failed") from exc

            status_code = getattr(response, "status_code", None)
            if isinstance(status_code, int) and status_code >= 500:
                last_error = UpstreamServiceError(
                    f"Upstream returned status {status_code}", response=response
                )
                self._record_failure(instance)
                excluded.add(instance.identity)
                if attempt < self.max_retries:
                    self._sleep(attempt)
                    continue
                return response

            self._record_success(instance)
            if hasattr(response, "status_code") and status_code is not None and status_code < 500:
                instance.healthy = True
            return response

        if isinstance(last_error, UpstreamServiceError) and last_error.response is not None:
            return last_error.response
        raise ServiceUnavailableError(f"Unable to reach service {service_name}")

    def _sleep(self, attempt: int) -> None:
        if self.backoff_factor == 0:
            return
        delay = self.backoff_factor * math.pow(2, attempt)
        if self.max_backoff:
            delay = min(delay, self.max_backoff)
        if delay > 0:
            self._sleep_func(delay)

    def _filter_instances(
        self, instances: Sequence[ServiceInstance], excluded: Iterable[str]
    ) -> List[ServiceInstance]:
        now = self._time_func()
        excluded_set = set(excluded)
        result: List[ServiceInstance] = []
        for instance in instances:
            if instance.identity in excluded_set:
                continue
            state = self._get_state(instance.identity)
            if state.opened_at is None:
                result.append(instance)
                continue
            if now - state.opened_at >= self.recovery_time:
                state.half_open = True
                state.opened_at = None
                result.append(instance)
        return result

    def _get_state(self, identity: str) -> _CircuitBreakerState:
        with self._lock:
            return self._circuits.setdefault(identity, _CircuitBreakerState())

    def _record_failure(self, instance: ServiceInstance) -> None:
        state = self._get_state(instance.identity)
        state.failures += 1
        instance.healthy = False
        if state.failures >= self.failure_threshold and state.opened_at is None:
            state.opened_at = self._time_func()
            state.half_open = False

    def _record_success(self, instance: ServiceInstance) -> None:
        state = self._get_state(instance.identity)
        state.failures = 0
        state.half_open = False
        state.opened_at = None
        instance.healthy = True

