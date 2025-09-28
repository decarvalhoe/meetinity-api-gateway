"""Configuration helpers for environment-aware setup."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping
import os

from dotenv import dotenv_values, load_dotenv

__all__ = [
    "EnvironmentSettings",
    "load_environment_settings",
    "build_hierarchical_tree",
    "log_configuration_snapshot",
    "lookup_hierarchical_value",
]


@dataclass(frozen=True)
class EnvironmentSettings:
    """Represents the environment configuration detected at runtime."""

    name: str
    loaded_files: tuple[str, ...]
    file_values: Mapping[str, str]
    hierarchical: Mapping[str, Any]

    def get(self, key: str) -> str | None:
        """Return the value for ``key`` considering hierarchical overrides."""

        value = os.getenv(key)
        if value is not None:
            return value
        return lookup_hierarchical_value(self.hierarchical, key)


def build_hierarchical_tree(
    values: Mapping[str, str], *, delimiter: str = "__"
) -> Mapping[str, Any]:
    """Build a nested mapping from ``KEY__CHILD`` style environment variables."""

    tree: dict[str, Any] = {}
    for raw_key, value in values.items():
        if delimiter not in raw_key:
            continue
        segments = [segment.strip().upper() for segment in raw_key.split(delimiter) if segment.strip()]
        if not segments:
            continue
        current: MutableMapping[str, Any] = tree
        for part in segments[:-1]:
            current = current.setdefault(part, {})  # type: ignore[assignment]
        current[segments[-1]] = value
    return tree


def lookup_hierarchical_value(tree: Mapping[str, Any], key: str) -> str | None:
    """Lookup ``key`` in ``tree`` by splitting on underscores."""

    if not key:
        return None
    segments = [segment.strip().upper() for segment in key.split("_") if segment.strip()]
    if not segments:
        return None
    current: Any = tree
    for part in segments:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
        if current is None:
            return None
    if isinstance(current, Mapping):
        return None
    return str(current)


def load_environment_settings(
    *, env: str | None = None, project_root: str | Path | None = None
) -> EnvironmentSettings:
    """Load environment settings supporting layered ``.env`` files."""

    root = Path(project_root or Path.cwd())
    name = (env or os.getenv("APP_ENV") or os.getenv("FLASK_ENV") or "development").strip()
    name = name or "development"
    ordered_files: list[Path] = [root / ".env", root / ".env.local"]
    slug = name.lower()
    ordered_files.extend([root / f".env.{slug}", root / f".env.{slug}.local"])

    loaded_files: list[str] = []
    file_values: dict[str, str] = {}
    for candidate in ordered_files:
        if not candidate.exists():
            continue
        load_dotenv(candidate, override=True)
        loaded_files.append(str(candidate))
        for key, value in dotenv_values(candidate).items():
            if value is not None:
                file_values[key] = value

    hierarchical = build_hierarchical_tree(dict(os.environ))
    return EnvironmentSettings(
        name=name,
        loaded_files=tuple(loaded_files),
        file_values=file_values,
        hierarchical=hierarchical,
    )


def _sanitize_value(key: str, value: Any) -> Any:
    markers = ("SECRET", "PASSWORD", "TOKEN", "KEY")
    upper_key = key.upper()
    if any(marker in upper_key for marker in markers):
        return "***"
    return value


def _sanitize_tree(tree: Mapping[str, Any]) -> Mapping[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in tree.items():
        if isinstance(value, Mapping):
            sanitized[key] = _sanitize_tree(value)
        else:
            sanitized[key] = _sanitize_value(key, value)
    return sanitized


def log_configuration_snapshot(
    *,
    logger: Any,
    settings: EnvironmentSettings,
    config: Mapping[str, Any],
    keys_of_interest: Iterable[str],
) -> None:
    """Log a sanitized snapshot of the runtime configuration."""

    snapshot = {
        key: _sanitize_value(key, config.get(key))
        for key in keys_of_interest
        if key in config
    }
    hierarchical = _sanitize_tree(settings.hierarchical)
    logger.info(
        "Runtime configuration initialised",
        extra={
            "environment": settings.name,
            "env_files": settings.loaded_files,
            "config_snapshot": snapshot,
            "hierarchical_overrides": hierarchical,
        },
    )
