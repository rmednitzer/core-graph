"""Static safety scan for migration 026_temporal_overlap_predicate_fix.sql.

ex_temporal_no_overlap must carry the SAME partial predicate as
uq_temporal_active_fact (020), otherwise lawful bitemporal supersession
(t_superseded set while still valid) is rejected. Live-DB coverage runs
via tests/schema/test_migrations.sh.
"""

from __future__ import annotations

import re
from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "migrations"
    / "026_temporal_overlap_predicate_fix.sql"
)


def _read() -> str:
    return MIGRATION_PATH.read_text()


def test_migration_present() -> None:
    assert MIGRATION_PATH.is_file()


def test_recreates_constraint_with_active_predicate() -> None:
    text = _read().lower()
    assert "drop constraint ex_temporal_no_overlap" in text
    assert "add constraint ex_temporal_no_overlap" in text
    # The defining fix: the exclusion must be partial over active facts.
    assert re.search(
        r"where\s*\(\s*t_invalid\s+is\s+null\s+and\s+t_superseded\s+is\s+null\s*\)",
        text,
    ), "ex_temporal_no_overlap must be predicated on active facts only."


def test_guarded_and_idempotent() -> None:
    text = _read().lower()
    # PG16 has no ALTER ... IF [NOT] EXISTS for constraints — must guard.
    assert text.count("pg_constraint") >= 2
    assert "conname = 'ex_temporal_no_overlap'" in text


def test_btree_gist_available() -> None:
    assert "create extension if not exists btree_gist" in _read().lower()
