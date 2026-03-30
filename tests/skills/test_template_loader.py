"""Tests for the Cypher template loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.mcp.tools.cypher_query import (
    load_parameter_schemas,
    load_query_templates,
    validate_params,
)


@pytest.fixture
def queries_dir(tmp_path: Path) -> Path:
    """Create a temporary queries directory with test templates."""
    # Create a valid template
    (tmp_path / "test_query.cypher").write_text("match (v {value: $value}) return v")
    (tmp_path / "test_query.json").write_text(
        json.dumps(
            {
                "description": "Test query",
                "parameters": {
                    "value": {"type": "string", "required": True, "description": "test value"}
                },
                "returns": "list",
                "max_depth": 1,
                "estimated_ms": 50,
            }
        )
    )

    # Create a template with optional params
    (tmp_path / "optional_params.cypher").write_text(
        "match (v:Host {canonical_key: $key}) return v limit $limit"
    )
    (tmp_path / "optional_params.json").write_text(
        json.dumps(
            {
                "description": "Query with optional params",
                "parameters": {
                    "key": {"type": "string", "required": True, "description": "host key"},
                    "limit": {"type": "integer", "required": False, "description": "limit"},
                },
                "returns": "list",
                "max_depth": 1,
                "estimated_ms": 50,
            }
        )
    )
    return tmp_path


def test_load_query_templates(queries_dir: Path) -> None:
    """Template loader reads all .cypher files."""
    templates = load_query_templates(queries_dir)
    assert "test_query" in templates
    assert "optional_params" in templates
    assert templates["test_query"] == "match (v {value: $value}) return v"


def test_load_query_templates_nonexistent_dir() -> None:
    """Loader returns empty dict for missing directory."""
    templates = load_query_templates(Path("/nonexistent/dir"))
    assert templates == {}


def test_load_parameter_schemas(queries_dir: Path) -> None:
    """Schema loader reads all .json files."""
    schemas = load_parameter_schemas(queries_dir)
    assert "test_query" in schemas
    assert schemas["test_query"]["parameters"]["value"]["required"] is True


def test_validate_params_required_present(queries_dir: Path) -> None:
    """Validation passes when required params are provided."""
    schemas = load_parameter_schemas(queries_dir)
    validate_params("test_query", {"value": "test"}, schemas)


def test_validate_params_required_missing(queries_dir: Path) -> None:
    """Validation raises ValueError when required params are missing."""
    schemas = load_parameter_schemas(queries_dir)
    with pytest.raises(ValueError, match="Missing required parameter"):
        validate_params("test_query", {}, schemas)


def test_validate_params_optional_missing(queries_dir: Path) -> None:
    """Validation passes when optional params are missing."""
    schemas = load_parameter_schemas(queries_dir)
    validate_params("optional_params", {"key": "abc"}, schemas)


def test_validate_params_no_schema() -> None:
    """Validation skips when no schema is available."""
    validate_params("unknown_template", {"anything": "goes"}, {})


def test_production_templates_loaded() -> None:
    """All production templates are loaded from api/mcp/skills/queries/."""
    from api.mcp.tools.cypher_query import PARAMETER_SCHEMAS, QUERY_TEMPLATES

    # Existing 8 templates
    assert "get_entity_by_value" in QUERY_TEMPLATES
    assert "get_neighbours" in QUERY_TEMPLATES
    assert "count_entities_by_label" in QUERY_TEMPLATES

    # New cross-domain templates
    assert "asset_full_summary" in QUERY_TEMPLATES
    assert "asset_compliance_status" in QUERY_TEMPLATES
    assert "asset_vulnerabilities" in QUERY_TEMPLATES
    assert "asset_active_alerts" in QUERY_TEMPLATES
    assert "asset_security_events" in QUERY_TEMPLATES
    assert "asset_topology" in QUERY_TEMPLATES
    assert "identity_access_map" in QUERY_TEMPLATES
    assert "identity_audit_trail" in QUERY_TEMPLATES
    assert "threat_actor_to_asset" in QUERY_TEMPLATES
    assert "alert_to_compliance_gap" in QUERY_TEMPLATES

    # Schemas loaded for all
    assert len(PARAMETER_SCHEMAS) == len(QUERY_TEMPLATES)
