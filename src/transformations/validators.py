"""Integration helpers for OpenAPI validation."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

from openapi_core import Spec
from openapi_core.datatypes import RequestParameters
from openapi_core.validation.exceptions import OpenAPIError
from werkzeug.datastructures import Headers, ImmutableMultiDict

if TYPE_CHECKING:  # pragma: no cover - circular import guard
    from .pipeline import RequestMessage, ResponseMessage


class OpenAPIValidationError(Exception):
    """Raised when validation against an OpenAPI schema fails."""


class _SimpleRequest:
    def __init__(
        self,
        *,
        host_url: str,
        path: str,
        method: str,
        parameters: RequestParameters,
        content_type: str,
        body: bytes | None,
    ) -> None:
        self.host_url = host_url
        self.path = path
        self.method = method
        self.parameters = parameters
        self.content_type = content_type
        self.body = body

    @property
    def full_url_pattern(self) -> str:
        base = self.host_url.rstrip("/")
        if not self.path.startswith("/"):
            return f"{base}/{self.path}"
        return f"{base}{self.path}"


class _SimpleResponse:
    def __init__(
        self,
        *,
        status_code: int,
        headers: Headers,
        content_type: str,
        data: bytes | None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers
        self.content_type = content_type
        self.data = data


class OpenAPIValidator:
    """Wraps openapi-core validators for request and response validation."""

    def __init__(
        self,
        *,
        spec_path: Path,
        request_validator_cls,
        response_validator_cls,
    ) -> None:
        self.spec_path = Path(spec_path)
        self.spec = Spec.from_file_path(self.spec_path)
        self.request_validator = request_validator_cls(self.spec)
        self.response_validator = response_validator_cls(self.spec)

    def validate_request(self, message: "RequestMessage") -> "RequestMessage":
        request = _SimpleRequest(
            host_url=message.host_url or "http://localhost",
            path=message.gateway_path,
            method=message.method.lower(),
            parameters=_build_parameters(message.headers, message.query_params),
            content_type=(message.content_type or "application/json").lower(),
            body=message.body,
        )
        try:
            self.request_validator.validate(request)
        except OpenAPIError as exc:  # pragma: no cover - exercised via pipeline tests
            raise OpenAPIValidationError(str(exc)) from exc
        return message

    def validate_response(
        self,
        message: "ResponseMessage",
        request_message: "RequestMessage" | None = None,
    ) -> "ResponseMessage":
        if request_message is None:
            return message
        request = _SimpleRequest(
            host_url=request_message.host_url or "http://localhost",
            path=request_message.gateway_path,
            method=request_message.method.lower(),
            parameters=_build_parameters(
                request_message.headers, request_message.query_params
            ),
            content_type=(request_message.content_type or "application/json").lower(),
            body=request_message.body,
        )
        response = _SimpleResponse(
            status_code=message.status_code,
            headers=Headers(message.headers),
            content_type=(message.content_type or "application/json").lower(),
            data=message.body,
        )
        try:
            self.response_validator.validate(request, response)
        except OpenAPIError as exc:  # pragma: no cover - exercised via pipeline tests
            raise OpenAPIValidationError(str(exc)) from exc
        return message


def _build_parameters(
    headers: Mapping[str, str], query_params: Sequence[tuple[str, str]]
) -> RequestParameters:
    header_values = Headers(list(headers.items()))
    query_values = ImmutableMultiDict(query_params)
    return RequestParameters(
        header=header_values,
        query=query_values,
        cookie=ImmutableMultiDict(),
        path={},
    )
