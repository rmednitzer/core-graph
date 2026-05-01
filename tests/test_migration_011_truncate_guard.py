"""Static safety check for migration 011_vector_dimensions.sql.

Phase-0 audit found that the original 011 silently truncated the entire
embeddings table when the column dimension changed. The fix requires the
operator to opt in via `app.allow_embedding_truncate` GUC.

This test ensures the guard is present in the migration source.
"""

from __future__ import annotations

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent / "schema" / "migrations" / "011_vector_dimensions.sql"
)


def _read() -> str:
    return MIGRATION_PATH.read_text()


def test_migration_present() -> None:
    assert MIGRATION_PATH.is_file()


def test_truncate_requires_explicit_guc() -> None:
    text = _read().lower()
    assert "app.allow_embedding_truncate" in text, (
        "Migration 011 must check `app.allow_embedding_truncate` GUC before truncating."
    )
    # The migration must raise rather than silently truncate when the GUC is absent.
    assert "raise exception" in text, (
        "Migration 011 must `RAISE EXCEPTION` when the truncate guard is not set."
    )


def test_truncate_followed_by_index_recreation() -> None:
    text = _read().lower()
    truncate_idx = text.find("truncate table embeddings")
    index_idx = text.find("create index idx_embeddings_hnsw")
    assert truncate_idx >= 0
    assert index_idx > truncate_idx
