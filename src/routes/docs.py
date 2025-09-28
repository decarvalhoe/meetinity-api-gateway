"""Blueprint exposing the generated OpenAPI documentation."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
import yaml

__all__ = ["create_docs_blueprint"]


def create_docs_blueprint() -> Blueprint:
    """Expose the OpenAPI specification via the ``/docs`` endpoint."""

    blueprint = Blueprint("docs", __name__)

    @blueprint.get("/docs")
    def serve_docs():
        spec = current_app.extensions.get("openapi_spec")
        if spec is None:
            from ..utils.openapi import generate_openapi_document

            spec = generate_openapi_document(current_app)
        fmt = request.args.get("format", "yaml").lower()
        if fmt == "json":
            return jsonify(spec)
        payload = yaml.safe_dump(spec, sort_keys=False)
        response = current_app.response_class(payload, mimetype="application/yaml")
        response.headers.setdefault("Cache-Control", "no-cache")
        return response

    return blueprint
