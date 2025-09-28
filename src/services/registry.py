"""Service discovery and load-balancing helpers."""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Mapping, MutableSequence, Sequence, Tuple


@dataclass(slots=True)
class ServiceInstance:
    """Describe a discovered service instance."""

    service_name: str
    url: str
    weight: int = 1
    healthy: bool = True
    metadata: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if self.weight < 1:
            self.weight = 1

    @property
    def identity(self) -> str:
        """Return a stable identifier for the instance."""

        return f"{self.service_name}:{self.url}"


class RegistryBackend:
    """Interface for registry backends."""

    def list_instances(self, service_name: str) -> Sequence[ServiceInstance]:  # pragma: no cover - documentation
        raise NotImplementedError


class StaticRegistryBackend(RegistryBackend):
    """Backend that serves instances from static configuration."""

    def __init__(self, services: Mapping[str, Sequence[ServiceInstance]]):
        self._services = services

    def list_instances(self, service_name: str) -> Sequence[ServiceInstance]:
        return list(self._services.get(service_name, ()))


class LoadBalancingStrategy:
    """Base interface for load balancing strategies."""

    def select(self, instances: Sequence[ServiceInstance]) -> ServiceInstance:  # pragma: no cover - documentation
        raise NotImplementedError


class RoundRobinStrategy(LoadBalancingStrategy):
    """Return instances in a round-robin fashion preferring healthy ones."""

    def __init__(self) -> None:
        self._counter = itertools.count()
        self._lock = threading.Lock()

    def select(self, instances: Sequence[ServiceInstance]) -> ServiceInstance:
        candidates = _prioritize_healthy(instances)
        if not candidates:
            raise ValueError("No instances available")

        with self._lock:
            index = next(self._counter)
            return candidates[index % len(candidates)]


class WeightedRoundRobinStrategy(LoadBalancingStrategy):
    """Return instances using deterministic weighted round robin."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sequence: MutableSequence[ServiceInstance] = []
        self._counter = 0
        self._fingerprint: Tuple[Tuple[str, int, bool], ...] | None = None

    def select(self, instances: Sequence[ServiceInstance]) -> ServiceInstance:
        candidates = _prioritize_healthy(instances)
        if not candidates:
            raise ValueError("No instances available")

        fingerprint = tuple((inst.identity, inst.weight, inst.healthy) for inst in candidates)
        if fingerprint != self._fingerprint:
            expanded: List[ServiceInstance] = []
            for inst in candidates:
                expanded.extend([inst] * inst.weight)
            self._sequence = expanded or list(candidates)
            self._counter = 0
            self._fingerprint = fingerprint

        with self._lock:
            if not self._sequence:
                raise ValueError("No instances available")
            inst = self._sequence[self._counter % len(self._sequence)]
            self._counter += 1
            return inst


class HealthAwareStrategy(LoadBalancingStrategy):
    """Prefer healthy instances while allowing graceful degradation."""

    def __init__(self) -> None:
        self._delegate = RoundRobinStrategy()

    def select(self, instances: Sequence[ServiceInstance]) -> ServiceInstance:
        healthy = [inst for inst in instances if inst.healthy]
        if healthy:
            return self._delegate.select(healthy)
        return self._delegate.select(instances)


StrategyFactory = Callable[[], LoadBalancingStrategy]


_STRATEGIES: Dict[str, StrategyFactory] = {
    "round_robin": RoundRobinStrategy,
    "weighted": WeightedRoundRobinStrategy,
    "health": HealthAwareStrategy,
}


def register_strategy(name: str, factory: StrategyFactory) -> None:
    """Register a new load balancing strategy."""

    _STRATEGIES[name.lower()] = factory


def create_strategy(name: str) -> LoadBalancingStrategy:
    """Create a load balancing strategy by name."""

    try:
        factory = _STRATEGIES[name.lower()]
    except KeyError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Unknown strategy '{name}'") from exc
    return factory()


def _prioritize_healthy(instances: Sequence[ServiceInstance]) -> List[ServiceInstance]:
    healthy = [inst for inst in instances if inst.healthy]
    return healthy or list(instances)


class ServiceRegistry:
    """High level interface to service discovery backends."""

    def __init__(
        self,
        backend: RegistryBackend,
        *,
        refresh_interval: float = 30.0,
        strategy_resolver: Callable[[str], LoadBalancingStrategy] | None = None,
    ) -> None:
        self._backend = backend
        self._refresh_interval = max(refresh_interval, 0.0)
        self._strategy_resolver = strategy_resolver
        self._cache: Dict[str, Tuple[float, List[ServiceInstance]]] = {}
        self._strategies: Dict[Tuple[str, str], LoadBalancingStrategy] = {}
        self._lock = threading.Lock()

    def get_instances(self, service_name: str, *, force_refresh: bool = False, now: float | None = None) -> List[ServiceInstance]:
        """Return cached instances, refreshing when needed."""

        import time

        timestamp = now if now is not None else time.monotonic()
        with self._lock:
            cached = self._cache.get(service_name)
            if (
                not cached
                or force_refresh
                or (self._refresh_interval and timestamp - cached[0] > self._refresh_interval)
            ):
                instances = list(self._backend.list_instances(service_name))
                self._cache[service_name] = (timestamp, instances)
            return list(self._cache[service_name][1])

    def select_instance(
        self,
        service_name: str,
        strategy: str,
        *,
        instances: Sequence[ServiceInstance] | None = None,
    ) -> ServiceInstance:
        """Select an instance using the requested strategy."""

        available = list(instances) if instances is not None else self.get_instances(service_name)
        if not available:
            raise LookupError(f"No instances registered for {service_name}")

        key = (service_name, strategy.lower())
        if key not in self._strategies:
            if self._strategy_resolver:
                self._strategies[key] = self._strategy_resolver(strategy)
            else:
                self._strategies[key] = create_strategy(strategy)

        return self._strategies[key].select(available)


def parse_static_instances(
    service_name: str,
    raw: str,
) -> List[ServiceInstance]:
    """Parse a comma separated list of ``url|weight`` definitions."""

    instances: List[ServiceInstance] = []
    for chunk in (part.strip() for part in raw.split(",") if part.strip()):
        if "|" in chunk:
            url, weight_str = chunk.split("|", 1)
            try:
                weight = int(weight_str)
            except ValueError:
                weight = 1
        else:
            url = chunk
            weight = 1
        instances.append(ServiceInstance(service_name=service_name, url=url.strip(), weight=weight))
    return instances


def create_service_registry(config: Mapping[str, object]) -> ServiceRegistry:
    """Instantiate a service registry from the Flask configuration."""

    service_name = str(config.get("USER_SERVICE_NAME", "user-service"))
    backend_name = str(config.get("SERVICE_DISCOVERY_BACKEND", "static")).lower()
    refresh_interval = float(config.get("SERVICE_DISCOVERY_REFRESH_INTERVAL", 30.0))

    static_value = str(config.get("USER_SERVICE_STATIC_INSTANCES", ""))
    instances = parse_static_instances(service_name, static_value)
    if not instances:
        url = str(config.get("USER_SERVICE_URL", ""))
        if url:
            instances.append(ServiceInstance(service_name=service_name, url=url))

    backend: RegistryBackend
    if backend_name == "static":
        backend = StaticRegistryBackend({service_name: instances})
    else:  # pragma: no cover - placeholder for future providers
        backend = StaticRegistryBackend({service_name: instances})

    return ServiceRegistry(backend, refresh_interval=refresh_interval)

