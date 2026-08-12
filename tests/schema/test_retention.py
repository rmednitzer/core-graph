"""Schema tests for serving-tier lifecycle (migration 039).

Requires a database with the migration chain applied; skipped when the stack
is not reachable, matching ``tests/integration/conftest.py``.

Two things are under test. The prune trigger, which stands in for the
``ON DELETE CASCADE`` that cannot be declared because ``embeddings`` has no
unique key on ``(graph_id, model_id)``; and the retention sweeper, which is
what finally writes the lifecycle columns migration 035 added.

Every test runs inside a transaction the fixture rolls back, so the sweeper is
free to act on the whole table.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from api.config import PG_DSN

pytestmark = pytest.mark.integration

MODEL = "t-retention"
DIM_SQL = (
    "select atttypmod as dim from pg_attribute "
    "where attrelid = 'retrieval_embeddings'::regclass and attname = 'embedding'"
)


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
    with psycopg.connect(PG_DSN, row_factory=dict_row) as c:
        c.autocommit = False
        yield c
        c.rollback()


@pytest.fixture
def model(conn):
    """A registered embedding model at whatever dimension the chain is on."""
    dim = conn.execute(DIM_SQL).fetchone()["dim"]
    conn.execute(
        "insert into embedding_models (model_id, dim) values (%s, %s) "
        "on conflict (model_id) do nothing",
        (MODEL, dim),
    )
    conn.execute(
        "select cg_register_retrieval_model(%s, 'embedding', 'test', 'test', 'test', %s)",
        (MODEL, dim),
    )
    return MODEL


def _subject(conn, model, graph_id, **cols):
    """One embeddings row plus its serving row, at a negative graph_id."""
    defaults = {"retrieval_active": True, "pinned": False, "retention_class": "durable"}
    defaults.update(cols)
    keys = ", ".join(defaults)
    marks = ", ".join(["%s"] * len(defaults))
    dim = conn.execute(DIM_SQL).fetchone()["dim"]
    conn.execute(
        f"insert into embeddings (graph_id, label, content, model, model_id, embedding, {keys}) "
        f"values (%s, 'RetDoc', 'c', %s, %s, array_fill(0.1::real, array[{dim}])::vector, {marks})",
        (graph_id, model, model, *defaults.values()),
    )
    conn.execute("select cg_sync_serving_tier()")


def _serving_count(conn, graph_id) -> int:
    return conn.execute(
        "select count(*) as n from retrieval_embeddings where graph_id = %s", (graph_id,)
    ).fetchone()["n"]


def _age(conn, graph_id, days) -> None:
    conn.execute(
        "update embeddings set created_at = now() - make_interval(days => %s) where graph_id = %s",
        (days, graph_id),
    )


def _active(conn, graph_id) -> bool:
    return conn.execute(
        "select retrieval_active from embeddings where graph_id = %s", (graph_id,)
    ).fetchone()["retrieval_active"]


# --- the prune trigger ------------------------------------------------------


def test_deleting_an_embedding_prunes_its_serving_row(conn, model):
    """Migration 012 deletes from `embeddings` daily. Before 039 nothing removed
    the serving row, so the orphan kept winning ANN slots and the caller
    silently got fewer than k candidates."""
    _subject(conn, model, -9100)
    assert _serving_count(conn, -9100) == 1

    conn.execute("delete from embeddings where graph_id = -9100")
    assert _serving_count(conn, -9100) == 0


def test_prune_is_statement_level_over_a_bulk_delete(conn, model):
    """012's cleanup deletes in bulk. A row-level trigger would issue one
    statement per row against a table carrying an HNSW index."""
    for gid in (-9101, -9102, -9103):
        _subject(conn, model, gid)

    conn.execute("delete from embeddings where graph_id between -9103 and -9101")
    row = conn.execute(
        "select count(*) as n from retrieval_embeddings where graph_id between -9103 and -9101"
    ).fetchone()
    assert row["n"] == 0


def test_a_surviving_duplicate_keeps_the_serving_row(conn, model):
    """The `not exists` re-check is what makes the trigger correct without a
    unique key. Two embeddings rows can share a (graph_id, model_id); removing
    one must not strip a subject that is still embedded."""
    _subject(conn, model, -9104)
    _subject(conn, model, -9104)  # same pair, second row

    dupes = conn.execute(
        "select copies from cg_serving_tier_duplicates where graph_id = -9104"
    ).fetchone()
    assert dupes["copies"] == 2

    conn.execute(
        "delete from embeddings where id = (select min(id) from embeddings where graph_id = -9104)"
    )
    assert _serving_count(conn, -9104) == 1

    conn.execute("delete from embeddings where graph_id = -9104")
    assert _serving_count(conn, -9104) == 0


# --- the sweeper ------------------------------------------------------------


def test_hot_rows_expire_after_the_window(conn, model):
    _subject(conn, model, -9110, retention_class="hot")
    _age(conn, -9110, 60)

    conn.execute("select cg_expire_retrieval()")
    assert _active(conn, -9110) is False


def test_durable_rows_never_age_out(conn, model):
    """035 defaults every row to durable, which is why the sweeper is inert on
    an existing deployment until a producer classifies rows."""
    _subject(conn, model, -9111, retention_class="durable")
    _age(conn, -9111, 900)

    conn.execute("select cg_expire_retrieval()")
    assert _active(conn, -9111) is True


def test_pinned_rows_are_exempt(conn, model):
    _subject(conn, model, -9112, retention_class="hot", pinned=True)
    _age(conn, -9112, 900)

    conn.execute("select cg_expire_retrieval()")
    assert _active(conn, -9112) is True


def test_expires_at_applies_whatever_the_class(conn, model):
    """The per-row override is the producer being explicit, so it outranks the
    class-based window rather than being filtered by it."""
    _subject(conn, model, -9113, retention_class="durable")
    conn.execute(
        "update embeddings set expires_at = now() - interval '1 day' where graph_id = -9113"
    )

    conn.execute("select cg_expire_retrieval()")
    assert _active(conn, -9113) is False


def test_a_nonpositive_window_raises(conn):
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("select cg_expire_retrieval(interval '0')")


# --- reconciliation ---------------------------------------------------------


def test_sync_removes_vectors_for_cooled_subjects(conn, model):
    """This is what makes ADR-0011's claim true: the serving table contains no
    cold rows, so the HNSW graph is bounded by the hot set."""
    _subject(conn, model, -9120, retention_class="hot")
    assert _serving_count(conn, -9120) == 1

    conn.execute("update embeddings set retrieval_active = false where graph_id = -9120")
    conn.execute("select cg_sync_serving_tier()")
    assert _serving_count(conn, -9120) == 0


def test_sync_restores_a_vector_when_a_subject_goes_active_again(conn, model):
    _subject(conn, model, -9121, retrieval_active=False)
    assert _serving_count(conn, -9121) == 0

    conn.execute("update embeddings set retrieval_active = true where graph_id = -9121")
    conn.execute("select cg_sync_serving_tier()")
    assert _serving_count(conn, -9121) == 1


def test_sync_is_idempotent(conn, model):
    _subject(conn, model, -9122)
    conn.execute("select cg_sync_serving_tier()")
    row = conn.execute("select * from cg_sync_serving_tier()").fetchone()
    assert row["removed"] == 0
    assert row["added"] == 0


def test_maintenance_expires_before_it_reconciles(conn, model):
    """Two cron entries would encode the ordering as a gap between two clock
    times; one entry calling both in order cannot drift."""
    _subject(conn, model, -9123, retention_class="hot")
    _age(conn, -9123, 60)

    row = conn.execute("select * from cg_retrieval_maintenance()").fetchone()
    assert row["expired"] >= 1
    assert row["removed"] >= 1
    assert _serving_count(conn, -9123) == 0


def test_the_job_is_scheduled(conn):
    row = conn.execute(
        "select schedule from cron.job where jobname = 'retrieval-maintenance'"
    ).fetchone()
    assert row is not None, "migration 039 did not schedule retrieval-maintenance"
    assert row["schedule"] == "30 3 * * *"
