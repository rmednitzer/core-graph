"""Static safety checks for migration 020_temporal_invariants.sql.

These are parse-only tests that catch the regressions documented in the
phase-0 audit:

  * `ADD CONSTRAINT IF NOT EXISTS` — invalid syntax in PostgreSQL 16.
  * `ADD COLUMN ... NOT NULL` without backfill — fails on tables with rows.

Full integration coverage (apply migration, verify constraints exist) is
performed by tests/schema/test_migrations.sh against a live PG container.
"""

from __future__ import annotations

import re
from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "migrations"
    / "020_temporal_invariants.sql"
)


def _read() -> str:
    return MIGRATION_PATH.read_text()


def test_migration_present() -> None:
    assert MIGRATION_PATH.is_file()


def _strip_sql_comments(text: str) -> str:
    """Strip `-- ...` line comments so static checks don't trip on docs."""
    lines = []
    for line in text.splitlines():
        comment_idx = line.find("--")
        if comment_idx >= 0:
            line = line[:comment_idx]
        lines.append(line)
    return "\n".join(lines)


def test_no_add_constraint_if_not_exists() -> None:
    """`ADD CONSTRAINT IF NOT EXISTS` is invalid in PG <= 16."""
    text = _strip_sql_comments(_read()).lower()
    assert "add constraint if not exists" not in text, (
        "Migration 020 still uses `ADD CONSTRAINT IF NOT EXISTS` (invalid PG 16 syntax). "
        "Wrap in DO block with pg_constraint catalog lookup."
    )


def test_constraints_use_pg_constraint_lookup() -> None:
    """All four constraints must be guarded by an existence check."""
    text = _read()
    expected_constraints = (
        "fk_temporal_superseded_by",
        "chk_temporal_valid_window",
        "chk_temporal_recorded_window",
        "ex_temporal_no_overlap",
    )
    for name in expected_constraints:
        guard = re.search(
            rf"pg_constraint\s+where\s+conname\s*=\s*'{re.escape(name)}'",
            text,
            re.IGNORECASE,
        )
        assert guard, f"Constraint {name} is not guarded by a pg_constraint lookup."


def test_required_columns_backfilled_before_set_not_null() -> None:
    """SET NOT NULL must come AFTER an UPDATE backfill for newly-added columns."""
    text = _read().lower()

    for col in ("mutation_actor", "mutation_reason"):
        update_idx = text.find(f"set {col} =")
        not_null_idx = text.find(f"alter column {col} set not null")
        assert update_idx >= 0, f"Missing backfill UPDATE for {col}"
        assert not_null_idx >= 0, f"Missing SET NOT NULL for {col}"
        assert update_idx < not_null_idx, (
            f"Column {col} is set NOT NULL before being backfilled; "
            f"would fail on tables with existing rows."
        )


def test_append_only_trigger_present() -> None:
    text = _read().lower()
    assert "trg_temporal_facts_no_delete" in text
    assert "before delete on temporal_facts" in text
