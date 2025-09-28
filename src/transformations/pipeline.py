"""Transformation pipeline implementation."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Any, Callable, Iterable, List, Mapping, Sequence

from openapi_core.validation.request.validators import V30RequestValidator
from openapi_core.validation.request.validators import V31RequestValidator
from openapi_core.validation.response.validators import V30ResponseValidator
from openapi_core.validation.response.validators import V31ResponseValidator

from .adapters import (
    convert_between_formats,
    graphql_to_rest,
    rest_to_graphql,
)
from .rules import load_transformation_rules
from .validators import OpenAPIValidationError as _ValidatorError
from .validators import OpenAPIValidator


class TransformationError(Exception):
    """Base error raised for transformation issues."""


class OpenAPIValidationError(TransformationError, _ValidatorError):
    """Raised when OpenAPI validation fails."""


@dataclass
class RequestMessage:
    """Representation of an incoming request for transformations."""

    method: str
    gateway_path: str
    upstream_path: str
    headers: Mapping[str, str]
    query_params: Sequence[tuple[str, str]]
    body: bytes | None
    content_type: str | None
    host_url: str = ""

    def copy(self, **kwargs: Any) -> "RequestMessage":
        return replace(self, **kwargs)


@dataclass
class ResponseMessage:
    """Representation of an upstream response for transformations."""

    status_code: int
    headers: Sequence[tuple[str, str]]
    body: bytes | None
    content_type: str | None

    def copy(self, **kwargs: Any) -> "ResponseMessage":
        return replace(self, **kwargs)


@dataclass
class _TransformationRule:
    """Internal representation of a transformation rule."""

    match: Mapping[str, Any]
    request_steps: List[Callable[[RequestMessage], RequestMessage]]
    response_steps: List[
        Callable[[ResponseMessage, RequestMessage | None], ResponseMessage]
    ]

    def matches(self, message: RequestMessage) -> bool:
        if not self.match:
            return True

        path_prefix = self.match.get("path_prefix")
        if path_prefix and not message.gateway_path.startswith(path_prefix):
            return False

        methods = self.match.get("methods")
        if methods and message.method.upper() not in {m.upper() for m in methods}:
            return False

        return True


class TransformationPipeline:
    """Pipeline that applies transformations based on configured rules."""

    def __init__(self, rules: Iterable[_TransformationRule]):
        self._rules = list(rules)

    def apply_request(self, message: RequestMessage) -> RequestMessage:
        for rule in self._matching_rules(message):
            for step in rule.request_steps:
                message = step(message)
        return message

    def apply_response(
        self,
        message: ResponseMessage,
        *,
        request_message: RequestMessage | None = None,
    ) -> ResponseMessage:
        request_message = request_message or RequestMessage(
            method="",
            gateway_path="",
            upstream_path="",
            headers={},
            query_params=(),
            body=None,
            content_type=None,
        )
        for rule in self._matching_rules(request_message):
            for step in rule.response_steps:
                message = step(message, request_message)
        return message

    def _matching_rules(self, message: RequestMessage) -> Iterable[_TransformationRule]:
        for rule in self._rules:
            if rule.matches(message):
                yield rule


def build_pipeline(
    rules: Mapping[str, Any] | str | Path,
    *,
    base_dir: str | Path | None = None,
) -> TransformationPipeline:
    """Build a :class:`TransformationPipeline` from transformation rules."""

    if not rules:
        return TransformationPipeline([])

    if not isinstance(rules, Mapping):
        rules = load_transformation_rules(rules, base_dir=base_dir)

    base_dir_path = Path(base_dir or ".").resolve()
    rule_entries: list[_TransformationRule] = []

    global_rule = _build_rule(rules, base_dir_path)
    if global_rule:
        rule_entries.append(global_rule)

    for route_rule in rules.get("routes", []) if isinstance(rules, Mapping) else []:
        built = _build_rule(route_rule, base_dir_path)
        if built:
            rule_entries.append(built)

    return TransformationPipeline(rule_entries)


def _build_rule(rule_data: Mapping[str, Any], base_dir: Path) -> _TransformationRule | None:
    match = rule_data.get("match", {}) if isinstance(rule_data, Mapping) else {}

    request_section = rule_data.get("request", {}) if isinstance(rule_data, Mapping) else {}
    response_section = rule_data.get("response", {}) if isinstance(rule_data, Mapping) else {}

    request_steps: list[Callable[[RequestMessage], RequestMessage]] = []
    response_steps: list[
        Callable[[ResponseMessage, RequestMessage | None], ResponseMessage]
    ] = []

    if request_section:
        headers_config = request_section.get("headers", {})
        if headers_config:
            request_steps.append(_build_header_step(headers_config))

        for conversion in request_section.get("body", {}).get("conversions", []):
            request_steps.append(_build_body_conversion_step(conversion, base_dir))

        validation_section = request_section.get("validation", {})
        openapi_config = validation_section.get("openapi") if isinstance(validation_section, Mapping) else None
        if openapi_config:
            validator = _build_openapi_validator(openapi_config, base_dir)
            request_steps.append(_wrap_request_validator(validator))
            response_steps.append(_wrap_response_validator(validator))

    if response_section:
        headers_config = response_section.get("headers", {})
        if headers_config:
            response_steps.append(_build_response_header_step(headers_config))

        for conversion in response_section.get("body", {}).get("conversions", []):
            response_steps.append(
                _build_response_body_conversion_step(conversion, base_dir)
            )

    if not request_steps and not response_steps:
        return None

    return _TransformationRule(match=match, request_steps=request_steps, response_steps=response_steps)


def _build_header_step(config: Mapping[str, Any]):
    headers_to_set = {str(k): str(v) for k, v in config.get("set", {}).items()}
    headers_to_remove = {h.lower() for h in config.get("remove", [])}

    def step(message: RequestMessage) -> RequestMessage:
        updated = dict(message.headers)
        for key, value in headers_to_set.items():
            updated[key] = value
        for header in headers_to_remove:
            keys = [k for k in updated if k.lower() == header]
            for key in keys:
                updated.pop(key, None)
        return message.copy(headers=updated)

    return step


def _build_response_header_step(config: Mapping[str, Any]):
    headers_to_set = [(str(k), str(v)) for k, v in config.get("set", {}).items()]
    headers_to_remove = {h.lower() for h in config.get("remove", [])}

    def step(
        message: ResponseMessage, _request: RequestMessage | None = None
    ) -> ResponseMessage:
        updated = [(k, v) for k, v in message.headers if k.lower() not in headers_to_remove]
        updated.extend(headers_to_set)
        return message.copy(headers=tuple(updated))

    return step


def _build_body_conversion_step(config: Mapping[str, Any], base_dir: Path):
    conversion_type = config.get("type", "format")

    if conversion_type == "format":
        from_format = config.get("from")
        to_format = config.get("to")

        def step(message: RequestMessage) -> RequestMessage:
            source_format = from_format or _guess_format(message.content_type)
            if not source_format or not to_format:
                return message

            converted, content_type = convert_between_formats(
                message.body,
                source_format,
                to_format,
            )
            headers = dict(message.headers)
            if content_type:
                headers["Content-Type"] = content_type
            return message.copy(body=converted, content_type=content_type, headers=headers)

        return step

    if conversion_type == "style":
        name = config.get("name")

        if name == "rest_to_graphql":
            def step(message: RequestMessage) -> RequestMessage:
                payload = _deserialize_body(message.body, message.content_type)
                converted = rest_to_graphql(
                    method=message.method,
                    path=message.gateway_path,
                    query_params=list(message.query_params),
                    body=payload,
                )
                body = json.dumps(converted).encode("utf-8")
                headers = dict(message.headers)
                headers["Content-Type"] = "application/json"
                return message.copy(body=body, content_type="application/json", headers=headers)

            return step

        if name == "graphql_to_rest":
            def step(message: RequestMessage) -> RequestMessage:
                payload = _deserialize_body(message.body, message.content_type)
                if not isinstance(payload, Mapping):
                    return message
                converted = graphql_to_rest(payload)
                body = converted.get("body")
                if body is not None:
                    body_bytes = json.dumps(body).encode("utf-8")
                    headers = dict(message.headers)
                    headers["Content-Type"] = "application/json"
                    return message.copy(
                        method=converted.get("method", message.method),
                        gateway_path=converted.get("path", message.gateway_path),
                        upstream_path=converted.get("path", message.upstream_path),
                        query_params=tuple(converted.get("query_params", message.query_params)),
                        body=body_bytes,
                        content_type="application/json",
                        headers=headers,
                    )
                return message

            return step

    return lambda message: message


def _build_response_body_conversion_step(config: Mapping[str, Any], base_dir: Path):
    conversion_type = config.get("type", "format")

    if conversion_type == "format":
        from_format = config.get("from")
        to_format = config.get("to")

        def step(
            message: ResponseMessage, _request: RequestMessage | None = None
        ) -> ResponseMessage:
            source_format = from_format or _guess_format(message.content_type)
            if not source_format or not to_format:
                return message
            converted, content_type = convert_between_formats(
                message.body,
                source_format,
                to_format,
            )
            headers = list(message.headers)
            headers = [
                (k, v)
                for k, v in headers
                if k.lower() != "content-type"
            ]
            if content_type:
                headers.append(("Content-Type", content_type))
            return message.copy(body=converted, content_type=content_type, headers=tuple(headers))

        return step

    if conversion_type == "style":
        name = config.get("name")

        if name == "graphql_to_rest":
            def step(
                message: ResponseMessage, request: RequestMessage | None = None
            ) -> ResponseMessage:
                payload = _deserialize_body(message.body, message.content_type)
                if not isinstance(payload, Mapping):
                    return message
                converted = graphql_to_rest(payload)
                body_data = converted.get("body")
                if body_data is None:
                    return message
                body_bytes = json.dumps(body_data).encode("utf-8")
                headers = [
                    (k, v)
                    for k, v in message.headers
                    if k.lower() != "content-type"
                ]
                headers.append(("Content-Type", "application/json"))
                return message.copy(body=body_bytes, content_type="application/json", headers=tuple(headers))

            return step

        if name == "rest_to_graphql":
            def step(
                message: ResponseMessage, request: RequestMessage | None = None
            ) -> ResponseMessage:
                payload = _deserialize_body(message.body, message.content_type)
                converted = rest_to_graphql(
                    method=request.method if request else "GET",
                    path=request.gateway_path if request else "/",
                    query_params=list(request.query_params) if request else [],
                    body=payload,
                )
                body_bytes = json.dumps(converted).encode("utf-8")
                headers = [
                    (k, v)
                    for k, v in message.headers
                    if k.lower() != "content-type"
                ]
                headers.append(("Content-Type", "application/json"))
                return message.copy(body=body_bytes, content_type="application/json", headers=tuple(headers))

            return step

    return lambda message, _request=None: message


def _build_openapi_validator(config: Mapping[str, Any], base_dir: Path) -> OpenAPIValidator:
    spec_path = config.get("spec")
    if not spec_path:
        raise TransformationError("OpenAPI validation requires a 'spec' path")
    resolved = Path(spec_path)
    if not resolved.is_absolute():
        resolved = (base_dir / resolved).resolve()

    version = str(config.get("version", "3.0")).strip()
    if version.startswith("3.1"):
        request_validator_cls = V31RequestValidator
        response_validator_cls = V31ResponseValidator
    else:
        request_validator_cls = V30RequestValidator
        response_validator_cls = V30ResponseValidator

    return OpenAPIValidator(
        spec_path=resolved,
        request_validator_cls=request_validator_cls,
        response_validator_cls=response_validator_cls,
    )


def _wrap_request_validator(validator: OpenAPIValidator):
    def step(message: RequestMessage) -> RequestMessage:
        try:
            return validator.validate_request(message)
        except _ValidatorError as exc:
            raise OpenAPIValidationError(str(exc)) from exc

    return step


def _wrap_response_validator(validator: OpenAPIValidator):
    def step(
        message: ResponseMessage, request: RequestMessage | None = None
    ) -> ResponseMessage:
        try:
            return validator.validate_response(message, request)
        except _ValidatorError as exc:
            raise OpenAPIValidationError(str(exc)) from exc

    return step


def _guess_format(content_type: str | None) -> str | None:
    if not content_type:
        return None
    content_type = content_type.lower()
    if "json" in content_type:
        return "json"
    if "xml" in content_type:
        return "xml"
    if "csv" in content_type:
        return "csv"
    return None


def _deserialize_body(body: bytes | None, content_type: str | None) -> Any:
    if body is None:
        return None

    fmt = _guess_format(content_type)
    if fmt == "json":
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    if fmt == "xml" or fmt == "csv":
        converted, _ = convert_between_formats(body, fmt, "json")
        try:
            return json.loads(converted.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    try:
        return json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
