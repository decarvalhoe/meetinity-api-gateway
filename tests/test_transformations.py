"""Tests for the configurable transformation pipeline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.transformations import (
    OpenAPIValidationError,
    RequestMessage,
    ResponseMessage,
    build_pipeline,
)


def _base_request(**overrides):
    defaults = {
        "method": "GET",
        "gateway_path": "/api/test",
        "upstream_path": "api/test",
        "headers": {},
        "query_params": tuple(),
        "body": None,
        "content_type": None,
        "host_url": "http://localhost",
    }
    defaults.update(overrides)
    return RequestMessage(**defaults)


def _base_response(**overrides):
    defaults = {
        "status_code": 200,
        "headers": tuple(),
        "body": None,
        "content_type": None,
    }
    defaults.update(overrides)
    return ResponseMessage(**defaults)


def test_header_injection_and_removal():
    rules = {
        "request": {
            "headers": {
                "set": {"X-Injected": "value"},
                "remove": ["X-Remove"],
            }
        }
    }
    pipeline = build_pipeline(rules)

    message = _base_request(headers={"X-Remove": "deprecated"})
    transformed = pipeline.apply_request(message)

    assert transformed.headers["X-Injected"] == "value"
    assert "X-Remove" not in transformed.headers


def test_json_to_xml_conversion():
    rules = {
        "request": {
            "body": {
                "conversions": [
                    {"type": "format", "from": "json", "to": "xml"},
                ]
            }
        }
    }
    pipeline = build_pipeline(rules)

    payload = {"username": "alice"}
    message = _base_request(
        body=json.dumps(payload).encode("utf-8"),
        content_type="application/json",
    )

    transformed = pipeline.apply_request(message)

    assert transformed.content_type == "application/xml"
    assert transformed.body is not None
    assert b"<username>alice</username>" in transformed.body


def test_rest_to_graphql_and_back():
    rules = {
        "request": {
            "body": {
                "conversions": [
                    {"type": "style", "name": "rest_to_graphql"},
                ]
            }
        },
        "response": {
            "body": {
                "conversions": [
                    {"type": "style", "name": "graphql_to_rest"},
                ]
            }
        },
    }
    pipeline = build_pipeline(rules)

    request_message = _base_request(
        method="POST",
        gateway_path="/api/users",
        upstream_path="api/users",
        headers={},
        body=json.dumps({"username": "alice"}).encode("utf-8"),
        content_type="application/json",
        query_params=(("verbose", "true"),),
    )

    transformed_request = pipeline.apply_request(request_message)
    assert transformed_request.body is not None
    graphql_payload = json.loads(transformed_request.body.decode("utf-8"))

    assert graphql_payload["variables"]["method"] == "POST"
    assert graphql_payload["variables"]["query"]["verbose"] == ["true"]
    assert graphql_payload["variables"]["body"] == {"username": "alice"}

    response_payload = {
        "query": graphql_payload["query"],
        "variables": {
            "method": "POST",
            "path": "/api/users",
            "query": {"verbose": ["true"]},
            "body": {"username": "alice"},
        },
    }
    response_message = _base_response(
        body=json.dumps(response_payload).encode("utf-8"),
        content_type="application/json",
        headers=(("Content-Type", "application/json"),),
    )

    transformed_response = pipeline.apply_response(
        response_message, request_message=transformed_request
    )

    assert transformed_response.body is not None
    converted_body = json.loads(transformed_response.body.decode("utf-8"))
    assert converted_body == {"username": "alice"}


def test_openapi_validation_errors():
    spec_path = Path("tests/data/sample_openapi.yaml")
    rules = {
        "request": {
            "validation": {
                "openapi": {"spec": str(spec_path)}
            }
        }
    }
    pipeline = build_pipeline(rules, base_dir=Path.cwd())

    invalid_request = _base_request(
        method="POST",
        gateway_path="/api/users",
        upstream_path="api/users",
        headers={"Content-Type": "application/json"},
        content_type="application/json",
        body=json.dumps({"email": "missing username"}).encode("utf-8"),
    )

    with pytest.raises(OpenAPIValidationError):
        pipeline.apply_request(invalid_request)

    valid_request = invalid_request.copy(
        body=json.dumps({"username": "bob"}).encode("utf-8")
    )
    pipeline.apply_request(valid_request)  # should not raise
