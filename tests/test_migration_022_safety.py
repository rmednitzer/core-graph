"""Static safety scan for migration 022_edge_tlp_denormalization.sql.

Integration coverage (apply migration to a real AGE-enabled PG, then run
RLS assertions) lives in tests/rls/test_edge_tlp.sql which is invoked by
the test_migrations.sh harness.
"""

from __future__ import annotations

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "migrations"
    / "022_edge_tlp_denormalization.sql"
)


def _read() -> str:
    return MIGRATION_PATH.read_text()


def test_migration_present() -> None:
    assert MIGRATION_PATH.is_file()


def test_adds_tlp_level_column() -> None:
    text = _read().lower()
    assert "add column if not exists tlp_level smallint not null default 0" in text


def test_check_constraint_pattern() -> None:
    text = _read().lower()
    assert "check (tlp_level between 0 and 4)" in text


def test_trigger_function_present() -> None:
    text = _read().lower()
    assert "create or replace function cg_edge_tlp_sync()" in text
    assert "trg_edge_tlp_sync" in text


def test_rls_policy_uses_column_not_jsonb() -> None:
    text = _read().lower()
    # Policy should test against the column, not extract JSONB on each row.
    assert "tlp_level <= " in text


def test_iam_floor_preserved() -> None:
    text = _read().lower()
    assert "iam_tlp_floor" in text
    assert "as restrictive" in text
    assert ">= 2" in text


def test_cascade_trigger_present() -> None:
    text = _read().lower()
    assert "cg_vertex_tlp_cascade" in text
    assert "deferrable initially deferred" in text


def test_helper_is_security_definer() -> None:
    text = _read().lower()
    # The helper must be SECURITY DEFINER so triggers can read across tables.
    assert "create or replace function cg_vertex_tlp_level" in text
    assert "security definer" in text
