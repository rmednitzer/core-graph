"""Schema tests for the retrieval model registry and lifecycle columns.

Covers migrations 034 and 035. Requires a database with the migration chain
applied; skipped when the stack is not reachable, matching
``tests/integration/conftest.py``.

The constraints here are the point of both migrations, so each is exercised in
both directions: a value that must be accepted and a value that must be
rejected. A check constraint that is never seen to reject is not evidence.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from api.config import PG_DSN

pytestmark = pytest.mark.integration


def _stack_is_running() -> bool:
    try:
        with psycopg.connect(PG_DSN) as conn:
            conn.execute("select 1")
        return True
    except Exception:
        return False


if not _stack_is_running():
    pytest.skip("Docker stack not running", allow_module_level=True)


@pytest.fixture
def conn():
    """A connection that rolls back, so the registry is never mutated."""
    with psycopg.connect(PG_DSN, row_factory=dict_row) as c:
        c.autocommit = False
        yield c
        c.rollback()


# ---------------------------------------------------------------------------
# 034 — registry structure and provenance
# ---------------------------------------------------------------------------


def test_pg_trgm_is_installed(conn):
    """ingest/resolver/ does entity resolution; trigram matching backs it."""
    row = conn.execute("select 1 from pg_extension where extname = 'pg_trgm'").fetchone()
    assert row is not None, "pg_trgm missing; migration 034 should have created it"


def test_registry_records_model_provenance_columns(conn):
    cols = {
        r["column_name"]
        for r in conn.execute(
            "select column_name from information_schema.columns "
            "where table_name = 'retrieval_models'"
        ).fetchall()
    }
    # `revision` is the load-bearing one: it pins the exact upstream commit,
    # so a stored vector is attributable to an immutable artifact.
    assert {"model_id", "kind", "provider", "repo", "revision", "dim", "active"} <= cols


def test_reranker_registers_without_a_dimension(conn):
    conn.execute(
        "select cg_register_retrieval_model("
        "'test-rr', 'reranker', 'jinaai', 'jinaai/x', 'deadbeef')"
    )
    row = conn.execute(
        "select kind, dim, active from retrieval_models where model_id = 'test-rr'"
    ).fetchone()
    assert row["kind"] == "reranker"
    assert row["dim"] is None
    assert row["active"] is True


def test_reranker_with_a_dimension_is_rejected(conn):
    """A reranker is not a vector space and must not be usable as one."""
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "select cg_register_retrieval_model('test-rr-bad', 'reranker', 'p', 'r', 'rev', 512)"
        )


def test_embedding_without_a_dimension_is_rejected(conn):
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "select cg_register_retrieval_model('test-emb-bad', 'embedding', 'p', 'r', 'rev')"
        )


def test_non_positive_embedding_dimension_is_rejected(conn):
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "select cg_register_retrieval_model('test-emb-zero', 'embedding', 'p', 'r', 'rev', 0)"
        )


def test_unknown_kind_is_rejected(conn):
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "select cg_register_retrieval_model('test-odd', 'summariser', 'p', 'r', 'rev', 512)"
        )


def test_deactivation_preserves_the_row(conn):
    """Vectors produced by a retired model stay attributable only while its
    row survives, so deactivation must not be deletion."""
    conn.execute(
        "select cg_register_retrieval_model('test-retire', 'embedding', 'p', 'r', 'rev123', 512)"
    )
    conn.execute("select cg_deactivate_retrieval_model('test-retire')")
    row = conn.execute(
        "select active, revision from retrieval_models where model_id = 'test-retire'"
    ).fetchone()
    assert row is not None
    assert row["active"] is False
    assert row["revision"] == "rev123"


# ---------------------------------------------------------------------------
# 035 — lifecycle columns
# ---------------------------------------------------------------------------


def test_lifecycle_columns_default_to_durable_and_active(conn):
    """Applying 035 must not change retrieval behaviour for existing rows."""
    row = conn.execute(
        "select column_name, column_default, is_nullable "
        "from information_schema.columns "
        "where table_name = 'embeddings' "
        "and column_name in ('retrieval_active', 'pinned', 'retention_class')"
    ).fetchall()
    defaults = {r["column_name"]: r["column_default"] for r in row}
    assert "true" in defaults["retrieval_active"]
    assert "false" in defaults["pinned"]
    assert "durable" in defaults["retention_class"]


def test_pinned_row_cannot_carry_an_expiry(conn):
    """The sweeper must not be able to age out something an operator pinned,
    whatever the sweeper's own logic does."""
    conn.execute(
        "insert into embedding_models (model_id, dim) values ('t-life', 768) on conflict do nothing"
    )
    # `model` is NOT NULL with no default, from migration 003. Omitting it
    # raises NotNullViolation and the CheckViolation below never gets reached.
    conn.execute(
        "insert into embeddings (graph_id, label, model, model_id) "
        "values (-991, 'T', 't-life', 't-life')"
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "update embeddings set pinned = true, expires_at = now() where graph_id = -991"
        )


def test_unknown_retention_class_value_is_rejected(conn):
    conn.execute(
        "insert into embedding_models (model_id, dim) values ('t-life2', 768) "
        "on conflict do nothing"
    )
    conn.execute(
        "insert into embeddings (graph_id, label, model, model_id) "
        "values (-992, 'T', 't-life2', 't-life2')"
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("update embeddings set retention_class = 'forever' where graph_id = -992")


# ---------------------------------------------------------------------------
# 035 — parity surface
# ---------------------------------------------------------------------------


def test_parity_view_excludes_rerankers(conn):
    """A reranker has no vector space, so counting it would report a
    permanent phantom gap."""
    conn.execute(
        "select cg_register_retrieval_model('test-rr-parity', 'reranker', 'p', 'r', 'rev')"
    )
    rows = {r["model_id"] for r in conn.execute("select model_id from cg_retrieval_parity")}
    assert "test-rr-parity" not in rows


def test_parity_view_reports_a_gap_for_a_model_with_no_vectors(conn):
    """A non-zero gap means hybrid fusion is searching a smaller corpus in one
    space than another, which shifts results with no error raised."""
    conn.execute(
        "select cg_register_retrieval_model('test-gap', 'embedding', 'p', 'r', 'rev', 768)"
    )
    row = conn.execute(
        "select active_subjects, vectors, gap from cg_retrieval_parity where model_id = 'test-gap'"
    ).fetchone()
    assert row is not None
    assert row["vectors"] == 0
    assert row["gap"] == row["active_subjects"]


def test_unrecorded_provenance_is_surfaced(conn):
    """Migration 034 backfills a placeholder rather than inventing provenance;
    the view is how that debt stays visible."""
    conn.execute(
        "insert into retrieval_models (model_id, kind, provider, repo, revision, dim) "
        "values ('test-unrec', 'embedding', 'unrecorded', 'unrecorded', 'unrecorded', 768)"
    )
    rows = {
        r["model_id"] for r in conn.execute("select model_id from cg_retrieval_models_unrecorded")
    }
    assert "test-unrec" in rows
