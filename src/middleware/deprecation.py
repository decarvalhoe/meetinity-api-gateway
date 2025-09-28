"""Middleware for emitting API version deprecation and sunset headers."""

from __future__ import annotations

from flask import Flask, g

__all__ = ["register_deprecation_middleware"]


def _select_mapping_value(mapping: dict[str, str], key: str | None) -> str | None:
    if not mapping:
        return None
    if key is not None and key in mapping:
        return mapping[key]
    if "" in mapping:
        return mapping[""]
    return None


def register_deprecation_middleware(app: Flask) -> None:
    """Attach hooks that emit RFC 8594 compatible deprecation headers."""

    @app.after_request
    def _apply_deprecation_headers(response):
        version = getattr(g, "api_version", app.config.get("API_DEFAULT_VERSION"))
        explicit = getattr(g, "api_version_explicit", False)
        deprecations: dict[str, str] = app.config.get("API_VERSION_DEPRECATIONS", {})
        sunsets: dict[str, str] = app.config.get("API_VERSION_SUNSETS", {})
        links: dict[str, str] = app.config.get("API_VERSION_DEPRECATION_LINKS", {})
        warnings_map: dict[str, str] = app.config.get("API_VERSION_WARNINGS", {})

        deprecation_value = _select_mapping_value(deprecations, version)
        if deprecation_value:
            response.headers.setdefault("Deprecation", deprecation_value)

        sunset_value = _select_mapping_value(sunsets, version)
        if sunset_value:
            response.headers.setdefault("Sunset", sunset_value)

        link_value = _select_mapping_value(links, version)
        if link_value:
            header_value = f"<{link_value}>; rel=\"deprecation\""
            existing_links = response.headers.getlist("Link")
            if header_value not in existing_links:
                response.headers.add("Link", header_value)

        warning_value = None
        if not explicit:
            warning_value = warnings_map.get("unversioned") or warnings_map.get("")
        if warning_value is None and version in warnings_map:
            warning_value = warnings_map[version]
        if warning_value is None and deprecation_value:
            warning_value = f'299 - "API version {version} is deprecated"'
        if warning_value:
            response.headers.add("Warning", warning_value)

        return response

    app.logger.debug(
        "Registered deprecation middleware for API versions: default=%s supported=%s",
        app.config.get("API_DEFAULT_VERSION"),
        app.config.get("API_VERSIONS"),
    )
