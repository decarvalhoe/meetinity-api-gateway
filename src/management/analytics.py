"""Analytics collection utilities for API management."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, Iterable

__all__ = ["AnalyticsCollector", "AnalyticsReport"]


@dataclass
class AnalyticsReport:
    """Structured summary of request analytics."""

    total_requests: int
    per_endpoint: Dict[str, int]
    per_method: Dict[str, int]
    per_status_code: Dict[str, int]
    per_version: Dict[str, int]
    average_latency_ms: Dict[str, float]
    api_key_usage: Dict[str, int]


class AnalyticsCollector:
    """Collect in-memory usage analytics for the gateway."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._total_requests = 0
            self._per_endpoint: Counter[str] = Counter()
            self._per_method: Counter[str] = Counter()
            self._per_status_code: Counter[str] = Counter()
            self._per_version: Counter[str] = Counter()
            self._api_key_usage: Counter[str] = Counter()
            self._latency_totals: Dict[str, float] = defaultdict(float)
            self._latency_counts: Counter[str] = Counter()

    def record_request(
        self,
        *,
        endpoint: str,
        method: str,
        status_code: int,
        version: str | None,
        duration: float,
        api_key: str | None = None,
    ) -> None:
        """Record a request/response observation."""

        with self._lock:
            self._total_requests += 1
            self._per_endpoint[endpoint] += 1
            self._per_method[method.upper()] += 1
            self._per_status_code[str(status_code)] += 1
            if version:
                self._per_version[version] += 1
            if api_key:
                self._api_key_usage[api_key] += 1
            key = f"{method.upper()} {endpoint}"
            self._latency_totals[key] += max(duration, 0.0)
            self._latency_counts[key] += 1

    def snapshot(self) -> AnalyticsReport:
        with self._lock:
            averages = {
                key: (self._latency_totals[key] / self._latency_counts[key]) * 1000.0
                for key in self._latency_counts
                if self._latency_counts[key]
            }
            return AnalyticsReport(
                total_requests=self._total_requests,
                per_endpoint=dict(self._per_endpoint),
                per_method=dict(self._per_method),
                per_status_code=dict(self._per_status_code),
                per_version=dict(self._per_version),
                average_latency_ms=averages,
                api_key_usage=dict(self._api_key_usage),
            )

    def export_report(self, fmt: str = "dict") -> AnalyticsReport | Dict[str, Any] | str:
        """Export the current analytics snapshot in various formats."""

        report = self.snapshot()
        if fmt == "dict":
            return report
        if fmt == "json":
            return {
                "total_requests": report.total_requests,
                "per_endpoint": report.per_endpoint,
                "per_method": report.per_method,
                "per_status_code": report.per_status_code,
                "per_version": report.per_version,
                "average_latency_ms": report.average_latency_ms,
                "api_key_usage": report.api_key_usage,
            }
        if fmt == "csv":
            rows = ["metric,value"]
            rows.append(f"total_requests,{report.total_requests}")
            for key, value in sorted(report.per_endpoint.items()):
                rows.append(f"endpoint::{key},{value}")
            for key, value in sorted(report.per_method.items()):
                rows.append(f"method::{key},{value}")
            for key, value in sorted(report.per_status_code.items()):
                rows.append(f"status::{key},{value}")
            for key, value in sorted(report.per_version.items()):
                rows.append(f"version::{key},{value}")
            for key, value in sorted(report.average_latency_ms.items()):
                rows.append(f"latency::{key},{value:.3f}")
            for key, value in sorted(report.api_key_usage.items()):
                rows.append(f"api_key::{key},{value}")
            return "\n".join(rows)
        raise ValueError(f"Unsupported analytics export format: {fmt}")

    def iter_usage(self) -> Iterable[tuple[str, int]]:
        """Iterate over endpoint usage counts (primarily for testing)."""

        report = self.snapshot()
        return report.per_endpoint.items()
