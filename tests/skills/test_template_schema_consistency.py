"""Tests for Cypher template and JSON schema consistency.

Validates that every .cypher template has a companion .json schema, that
required parameters appear in the Cypher template, and that every $param
reference in the template has a schema entry.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

QUERIES_DIR = Path("api/mcp/skills/queries")

# Collect all template stems
_cypher_files = sorted(QUERIES_DIR.glob("*.cypher"))
_json_files = sorted(QUERIES_DIR.glob("*.json"))
_cypher_stems = {f.stem for f in _cypher_files}
_json_stems = {f.stem for f in _json_files}

# Regex for $param_name references in Cypher (excluding $$ dollar-quoting)
_PARAM_RE = re.compile(r"(?<!\$)\$([a-zA-Z_][a-zA-Z0-9_]*)")


def _extract_cypher_params(cypher_text: str) -> set[str]:
    """Extract $param_name references from Cypher template text.

    Ignores content inside $$ dollar-quoting (SQL wrapper boundaries).
    """
    # Remove any $$ ... $$ blocks (dollar-quoted SQL boundaries)
    cleaned = re.sub(r"\$\$.*?\$\$", "", cypher_text, flags=re.DOTALL)
    return set(_PARAM_RE.findall(cleaned))


class TestCompanionSchemaExists:
    """Every .cypher file must have a companion .json file."""

    @pytest.mark.parametrize("cypher_file", _cypher_files, ids=lambda f: f.stem)
    def test_json_exists(self, cypher_file: Path) -> None:
        json_file = cypher_file.with_suffix(".json")
        assert json_file.exists(), (
            f"Missing companion schema: {json_file.name} for {cypher_file.name}"
        )


class TestRequiredParamsInTemplate:
    """Every required parameter in the JSON must appear as $param in the Cypher."""

    @pytest.mark.parametrize("cypher_file", _cypher_files, ids=lambda f: f.stem)
    def test_required_params_referenced(self, cypher_file: Path) -> None:
        json_file = cypher_file.with_suffix(".json")
        if not json_file.exists():
            pytest.skip(f"No companion JSON for {cypher_file.name}")

        schema = json.loads(json_file.read_text())
        params = schema.get("parameters", {})
        cypher_text = cypher_file.read_text()
        cypher_params = _extract_cypher_params(cypher_text)

        for param_name, param_def in params.items():
            if param_def.get("required", False):
                assert param_name in cypher_params, (
                    f"Required param '{param_name}' from {json_file.name} "
                    f"not found as ${param_name} in {cypher_file.name}"
                )


class TestTemplateParamsInSchema:
    """Every $param in the Cypher template must have a schema entry."""

    @pytest.mark.parametrize("cypher_file", _cypher_files, ids=lambda f: f.stem)
    def test_template_params_have_schema(self, cypher_file: Path) -> None:
        json_file = cypher_file.with_suffix(".json")
        if not json_file.exists():
            pytest.skip(f"No companion JSON for {cypher_file.name}")

        schema = json.loads(json_file.read_text())
        schema_params = set(schema.get("parameters", {}).keys())
        cypher_text = cypher_file.read_text()
        cypher_params = _extract_cypher_params(cypher_text)

        for param in cypher_params:
            assert param in schema_params, (
                f"${param} in {cypher_file.name} has no entry in {json_file.name}"
            )
