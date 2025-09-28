"""Utilities to load transformation rules from YAML or JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import yaml


class TransformationRuleError(ValueError):
    """Raised when transformation rules cannot be loaded."""


def load_transformation_rules(
    source: str | Path | Mapping[str, Any],
    *,
    base_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Load transformation rules from a mapping, file path or raw string.

    Args:
        source: A mapping of rules, a path to a YAML/JSON file or a raw
            YAML/JSON string.
        base_dir: Optional base directory used to resolve relative paths when
            ``source`` refers to a file path.

    Returns:
        A dictionary representing the transformation rules.

    Raises:
        TransformationRuleError: If the rules cannot be parsed or are invalid.
    """

    if isinstance(source, Mapping):
        return dict(source)

    if isinstance(source, Path):
        path = source
    else:
        path_candidate = Path(str(source))
        path = path_candidate if path_candidate.exists() else None

    if path:
        if not path.is_absolute() and base_dir:
            path = Path(base_dir) / path
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - hard failure
            raise TransformationRuleError(f"Cannot read rules file: {exc}") from exc
    else:
        text = str(source)

    text = text.strip()
    if not text:
        return {}

    try:
        if text.lstrip().startswith("{"):
            return json.loads(text)
    except json.JSONDecodeError:
        pass

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise TransformationRuleError("Invalid YAML transformation rules") from exc

    if not isinstance(data, dict):
        raise TransformationRuleError("Transformation rules must be a mapping")

    return data
