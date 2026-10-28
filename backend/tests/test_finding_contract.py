import pytest

from app.schemas.enums import EntityType, Severity, VectorType
from app.services.finding_contract import InvalidFindingError, prepare_finding
from collectors.registry import registry


def test_every_registered_collector_has_valid_metadata():
    collectors = registry.get_all_collectors()
    assert collectors
    assert len(collectors) == len(set(collectors))

    for name, collector_class in collectors.items():
        metadata = collector_class.metadata
        assert metadata.name == name
        assert metadata.vector in VectorType._value2member_map_
        assert metadata.description.strip()
        assert not metadata.requires_api_key or metadata.api_key_env


def test_prepare_finding_matches_api_taxonomy_and_json_shape():
    safe = prepare_finding({
        "vector_type": "services",
        "entity_type": "cve",
        "entity_value": " CVE-2026-0001 ",
        "severity": "high",
        "confidence": "0.95",
        "source_module": "fixture",
        "raw_data": {"provider": "fixture"},
        "normalized_data": {"score": 9.1},
        "tags": "verified",
    })

    assert safe == {
        "vector_type": "SERVICES",
        "entity_type": "CVE",
        "entity_value": "CVE-2026-0001",
        "severity": "HIGH",
        "confidence": 0.95,
        "source_module": "fixture",
        "raw_data": {"provider": "fixture"},
        "normalized_data": {"score": 9.1},
        "tags": ["verified"],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("vector_type", "UNKNOWN_VECTOR"),
        ("entity_type", "UNKNOWN_ENTITY"),
        ("severity", "URGENT"),
        ("confidence", 1.1),
        ("raw_data", ["not", "an", "object"]),
        ("normalized_data", "not an object"),
    ],
)
def test_prepare_finding_rejects_values_the_api_cannot_serialize(field, value):
    finding = {
        "vector_type": VectorType.INFRASTRUCTURE.value,
        "entity_type": EntityType.SUBDOMAIN.value,
        "entity_value": "www.example.com",
        "severity": Severity.INFO.value,
        "confidence": 1.0,
        "source_module": "fixture",
        "raw_data": {},
        "normalized_data": {},
        "tags": [],
    }
    finding[field] = value

    with pytest.raises(InvalidFindingError):
        prepare_finding(finding)


@pytest.mark.parametrize("field", ["entity_type", "entity_value", "source_module"])
def test_prepare_finding_rejects_missing_required_identity(field):
    finding = {
        "vector_type": "INFRASTRUCTURE",
        "entity_type": "SUBDOMAIN",
        "entity_value": "www.example.com",
        "source_module": "fixture",
    }
    finding.pop(field)

    with pytest.raises(InvalidFindingError):
        prepare_finding(finding)
