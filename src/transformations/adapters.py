"""Data conversion adapters used by the transformation pipeline."""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable, Mapping, Sequence
from xml.etree import ElementTree as ET


def convert_between_formats(
    body: bytes | None,
    source_format: str,
    target_format: str,
) -> tuple[bytes | None, str | None]:
    """Convert ``body`` between textual formats."""

    if body is None:
        return None, _content_type_for(target_format)

    source_format = source_format.lower()
    target_format = target_format.lower()

    if source_format == target_format:
        return body, _content_type_for(target_format)

    data = _decode(body, source_format)
    converted = _encode(data, target_format)
    return converted, _content_type_for(target_format)


def rest_to_graphql(
    *,
    method: str,
    path: str,
    query_params: Sequence[tuple[str, str]] | None,
    body: Any,
) -> dict[str, Any]:
    """Convert a REST-like request description into a GraphQL payload."""

    method = (method or "GET").upper()
    normalized_path = path or "/"
    field_name = _normalize_field_name(normalized_path)
    operation_type = "query" if method == "GET" else "mutation"
    operation_name = field_name.title().replace("_", "") or "Root"

    variables: dict[str, Any] = {"method": method, "path": normalized_path}
    if query_params:
        normalized_query: dict[str, list[str]] = {}
        for key, value in query_params:
            normalized_query.setdefault(key, []).append(str(value))
        variables["query"] = normalized_query
    if body is not None:
        variables["body"] = body

    query = f"{operation_type} {operation_name} {{ {field_name or 'root'} }}"
    return {"query": query, "variables": variables}


def graphql_to_rest(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a GraphQL payload into a simplified REST description."""

    variables = payload.get("variables")
    if not isinstance(variables, Mapping):
        return {}

    method = str(variables.get("method", "POST")).upper()
    path = str(variables.get("path", "/"))
    query_params: list[tuple[str, str]] = []
    raw_query = variables.get("query")
    if isinstance(raw_query, Mapping):
        for key, value in raw_query.items():
            if isinstance(value, (list, tuple)):
                query_params.extend((key, str(item)) for item in value)
            else:
                query_params.append((key, str(value)))

    body = variables.get("body")

    return {
        "method": method,
        "path": path,
        "query_params": tuple(query_params),
        "body": body,
    }


def _decode(body: bytes, fmt: str) -> Any:
    text = body.decode("utf-8")
    if fmt == "json":
        return json.loads(text)
    if fmt == "xml":
        return _xml_to_data(text)
    if fmt == "csv":
        return _csv_to_data(text)
    raise ValueError(f"Unsupported format: {fmt}")


def _encode(data: Any, fmt: str) -> bytes:
    if fmt == "json":
        return json.dumps(data).encode("utf-8")
    if fmt == "xml":
        return _data_to_xml(data)
    if fmt == "csv":
        return _data_to_csv(data)
    raise ValueError(f"Unsupported format: {fmt}")


def _content_type_for(fmt: str | None) -> str | None:
    if fmt == "json":
        return "application/json"
    if fmt == "xml":
        return "application/xml"
    if fmt == "csv":
        return "text/csv"
    return None


def _normalize_field_name(path: str) -> str:
    stripped = path.strip("/")
    if not stripped:
        return "root"
    return stripped.replace("/", "_")


def _xml_to_data(text: str) -> Any:
    root = ET.fromstring(text)
    return _element_to_value(root)


def _element_to_value(element: ET.Element) -> Any:
    children = list(element)
    if not children:
        text = element.text or ""
        return text.strip()

    result: dict[str, Any] = {}
    for child in children:
        value = _element_to_value(child)
        if child.tag in result:
            existing = result[child.tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[child.tag] = [existing, value]
        else:
            result[child.tag] = value
    return result


def _data_to_xml(data: Any) -> bytes:
    root = ET.Element("root")
    _append_value(root, data)
    return ET.tostring(root, encoding="utf-8")


def _append_value(element: ET.Element, value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = ET.SubElement(element, str(key))
            _append_value(child, item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            child = ET.SubElement(element, "item")
            _append_value(child, item)
    else:
        element.text = "" if value is None else str(value)


def _csv_to_data(text: str) -> Any:
    reader = csv.DictReader(io.StringIO(text))
    return [row for row in reader]


def _data_to_csv(data: Any) -> bytes:
    rows: list[Mapping[str, Any]]
    if isinstance(data, Mapping):
        rows = [data]
    elif isinstance(data, Iterable):
        rows = [row for row in data if isinstance(row, Mapping)]
    else:
        rows = [{"value": data}]

    if not rows:
        return b""

    fieldnames = sorted({key for row in rows for key in row.keys()})
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in fieldnames})
    return buffer.getvalue().encode("utf-8")
