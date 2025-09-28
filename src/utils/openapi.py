"""Utilities for generating the OpenAPI description of the gateway."""

from __future__ import annotations

import os
from typing import Any, Dict

import yaml
from flask import Flask

from ..routes import PROXY_ROUTE_DEFINITIONS

__all__ = ["generate_openapi_document"]


def _operation_metadata(
    app: Flask,
    definition,
    method: str,
    version: str,
    *,
    explicit: bool,
    include_subpath: bool,
    context: str,
) -> Dict[str, Any]:
    responses: Dict[str, Any] = {
        "200": {"description": "Successful proxy response."},
        "502": {"description": "Upstream service returned an error."},
    }
    if definition.requires_jwt:
        responses.setdefault("401", {"description": "Missing or invalid JWT."})
    if definition.rate_limit_config:
        responses.setdefault("429", {"description": "Rate limit exceeded."})

    description = definition.description or definition.summary or ""
    if not explicit:
        warning = app.config.get("API_VERSION_WARNINGS", {}).get("unversioned") or app.config.get(
            "API_VERSION_WARNINGS", {}
        ).get("")
        if warning:
            description = f"{description}\n\n**Warning:** {warning}" if description else warning

    operation: Dict[str, Any] = {
        "operationId": f"{version}_{definition.name}_{context}_{method.lower()}",
        "summary": definition.summary or definition.name.title(),
        "description": description,
        "tags": list(definition.tags),
        "responses": responses,
        "x-api-version": version,
    }
    if definition.requires_jwt and method.upper() not in {"OPTIONS"}:
        operation["security"] = [{"bearerAuth": []}]
    else:
        operation["security"] = []
    if include_subpath:
        operation["parameters"] = [
            {
                "name": "subpath",
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": "Additional path segments forwarded upstream.",
            }
        ]
    return operation


def generate_openapi_document(app: Flask) -> Dict[str, Any]:
    """Generate and persist the OpenAPI specification for the gateway."""

    versions = tuple(app.config.get("API_VERSIONS", ("v1",)))
    default_version = app.config.get("API_DEFAULT_VERSION", versions[0] if versions else "v1")
    deprecations = app.config.get("API_VERSION_DEPRECATIONS", {})

    paths: Dict[str, Dict[str, Any]] = {}
    for definition in PROXY_ROUTE_DEFINITIONS:
        base_path = definition.gateway_path
        for method in definition.methods:
            operation = _operation_metadata(
                app,
                definition,
                method,
                default_version,
                explicit=False,
                include_subpath=False,
                context="root",
            )
            if default_version in deprecations or "" in deprecations:
                operation["deprecated"] = True
            paths.setdefault(base_path, {})[method.lower()] = operation
            sub_operation = _operation_metadata(
                app,
                definition,
                method,
                default_version,
                explicit=False,
                include_subpath=True,
                context="subpath",
            )
            if default_version in deprecations or "" in deprecations:
                sub_operation["deprecated"] = True
            paths.setdefault(f"{base_path}/{{subpath}}", {})[method.lower()] = sub_operation

        for version in versions:
            prefixed = f"/{version}{base_path}"
            for method in definition.methods:
                op = _operation_metadata(
                    app,
                    definition,
                    method,
                    version,
                    explicit=True,
                    include_subpath=False,
                    context="root",
                )
                if version in deprecations:
                    op["deprecated"] = True
                paths.setdefault(prefixed, {})[method.lower()] = op
                sub_op = _operation_metadata(
                    app,
                    definition,
                    method,
                    version,
                    explicit=True,
                    include_subpath=True,
                    context="subpath",
                )
                if version in deprecations:
                    sub_op["deprecated"] = True
                paths.setdefault(f"{prefixed}/{{subpath}}", {})[method.lower()] = sub_op

    spec: Dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": "Meetinity API Gateway",
            "version": default_version,
            "description": "Programmatic access to Meetinity user services via the gateway.",
        },
        "servers": [
            {"url": "/", "description": "Default routing"},
        ],
        "tags": [
            {"name": tag}
            for tag in sorted({tag for definition in PROXY_ROUTE_DEFINITIONS for tag in definition.tags})
        ],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
    }

    output_path = app.config.get("OPENAPI_OUTPUT_PATH")
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(spec, handle, sort_keys=False)

    app.extensions["openapi_spec"] = spec
    return spec
