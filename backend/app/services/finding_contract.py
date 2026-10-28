"""Canonical validation and coercion for findings before database storage.

Collectors intentionally return plain dictionaries so they stay lightweight.
This module is the boundary that prevents malformed collector output from
reaching Postgres and later failing API response validation.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

from app.schemas.enums import EntityType, Severity, VectorType


class InvalidFindingError(ValueError):
    """Raised when a collector result does not satisfy the finding contract."""


def _enum_value(value: Any) -> str:
    return str(value.value if isinstance(value, Enum) else value).strip().upper()


def _json_object(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    raise InvalidFindingError(f"{field_name} must be a JSON object")


def prepare_finding(
    finding: Mapping[str, Any],
    *,
    default_vector: str = "INFRASTRUCTURE",
    default_severity: str = "INFO",
    default_confidence: float = 0.5,
    default_source: str = "",
) -> dict[str, Any]:
    """Return a database-safe finding or raise ``InvalidFindingError``.

    The accepted taxonomies are the same enums used by the API response
    schema. This makes storage and serialization one contract instead of two
    independent, stringly typed assumptions.
    """
    if not isinstance(finding, Mapping):
        raise InvalidFindingError("finding must be a mapping")

    vector_type = _enum_value(finding.get("vector_type", default_vector))
    if vector_type not in VectorType._value2member_map_:
        raise InvalidFindingError(f"unknown vector_type: {vector_type!r}")

    entity_type = _enum_value(finding.get("entity_type", ""))
    if entity_type not in EntityType._value2member_map_:
        raise InvalidFindingError(f"unknown entity_type: {entity_type!r}")

    severity = _enum_value(finding.get("severity", default_severity))
    if severity not in Severity._value2member_map_:
        raise InvalidFindingError(f"unknown severity: {severity!r}")

    entity_value = finding.get("entity_value")
    if isinstance(entity_value, Mapping):
        entity_value = entity_value.get("sha256", entity_value.get("value"))
    if entity_value is None:
        raise InvalidFindingError("entity_value is required")
    entity_value = str(entity_value).strip()
    if not entity_value:
        raise InvalidFindingError("entity_value must not be empty")

    source_module = str(finding.get("source_module", default_source) or "").strip()
    if not source_module:
        raise InvalidFindingError("source_module is required")

    try:
        confidence = float(finding.get("confidence", default_confidence))
    except (TypeError, ValueError) as exc:
        raise InvalidFindingError("confidence must be numeric") from exc
    if not 0.0 <= confidence <= 1.0:
        raise InvalidFindingError("confidence must be between 0 and 1")

    tags = finding.get("tags", []) or []
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, (list, tuple, set)):
        raise InvalidFindingError("tags must be a list of strings")

    return {
        "vector_type": vector_type,
        "entity_type": entity_type,
        "entity_value": entity_value,
        "severity": severity,
        "confidence": confidence,
        "source_module": source_module,
        "raw_data": _json_object(finding.get("raw_data", {}), "raw_data"),
        "normalized_data": _json_object(
            finding.get("normalized_data", {}), "normalized_data"
        ),
        "tags": [str(tag) for tag in tags if str(tag).strip()],
    }
