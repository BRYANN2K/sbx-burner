"""Minimal JSON Schema validator (stdlib only).

Supports the keywords used by the schemas in ``lab/schema``: ``type``,
``enum``, ``const``, ``required``, ``properties``, ``additionalProperties``,
``items``, ``minItems``, ``maxItems``, ``minLength``, ``maxLength``, ``pattern``, ``minimum``, ``maximum``
and local ``$ref`` (``#/$defs/...``).
"""

from __future__ import annotations

import re
from typing import Any

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _is_type(value: Any, name: str) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[name])


def validate(instance: Any, schema: dict[str, Any], root: dict[str, Any] | None = None) -> list[str]:
    """Return a list of human-readable errors (empty when valid)."""
    errors: list[str] = []
    _validate(instance, schema, root or schema, "$", errors)
    return errors


def _validate(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str, errors: list[str]) -> None:
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise ValueError(f"only local $ref is supported: {ref}")
        target: Any = root
        for part in ref[2:].split("/"):
            target = target[part]
        _validate(value, target, root, path, errors)
        return

    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, t) for t in types):
            errors.append(f"{path}: expected {' or '.join(types)}, got {type(value).__name__}")
            return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not one of {schema['enum']}")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: string is shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: string is longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match {schema['pattern']!r}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} is below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: {value} is above maximum {schema['maximum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: needs at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: has more than {schema['maxItems']} item(s)")
        if "items" in schema:
            for i, item in enumerate(value):
                _validate(item, schema["items"], root, f"{path}[{i}]", errors)
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key {key!r}")
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in value:
                _validate(value[key], sub, root, f"{path}.{key}", errors)
        extra = schema.get("additionalProperties", True)
        for key in value:
            if key in props:
                continue
            if extra is False:
                errors.append(f"{path}: unexpected key {key!r}")
            elif isinstance(extra, dict):
                _validate(value[key], extra, root, f"{path}.{key}", errors)
