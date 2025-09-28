"""Route registration helpers for the API gateway."""

from __future__ import annotations

from flask import Flask

from .proxy import PROXY_ROUTE_DEFINITIONS, create_proxy_blueprint

__all__ = ["PROXY_ROUTE_DEFINITIONS", "register_versioned_proxy_blueprints"]


def register_versioned_proxy_blueprints(app: Flask) -> None:
    """Register proxy blueprints for each configured API version."""

    versions = tuple(app.config.get("API_VERSIONS", ("v1",)))
    default_version = app.config.get("API_DEFAULT_VERSION", versions[0] if versions else "v1")
    app.extensions.setdefault(
        "api_versions",
        {
            "supported": versions,
            "default": default_version,
            "aliases": [""],
        },
    )

    # Unversioned blueprint always maps to the default version for backwards compatibility.
    app.register_blueprint(create_proxy_blueprint(None, default_version))

    for version in versions:
        app.register_blueprint(create_proxy_blueprint(version, default_version))
