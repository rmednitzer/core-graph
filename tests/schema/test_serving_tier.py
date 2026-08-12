"""Schema tests for the retrieval serving tier (migration 036).

Requires a database with the migration chain applied; skipped when the stack
is not reachable, matching ``tests/integration/conftest.py``.

The properties worth asserting are the ones that are invisible in a passing
query: that the table holds only retrieval-active subjects, that each model
gets its own partial index, and that a reranker never acquires one.
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
    with psycopg.connect(PG_DSN, row_factory=dict_row) as c:
        c.autocommit = False
        yield c
        c.rollback()


def test_serving_vector_is_halfvec(conn):
    """The whole point of 036 is one native halfvec, not a full-precision
    column with a derived twin."""
    row = conn.execute(
        "select format_type(a.atttypid, a.atttypmod) as t "
        "from pg_attribute a "
        "where a.attrelid = 'retrieval_embeddings'::regclass "
        "and a.attname = 'embedding' and not a.attisdropped"
    ).fetchone()
    assert row["t"].startswith("halfvec(")


def test_serving_dim_tracks_embeddings_column(conn):
    """036 reads the dimension from the catalogue rather than hardcoding it,
    so the two columns cannot drift apart."""
    rows = conn.execute(
        "select c.relname, format_type(a.atttypid, a.atttypmod) as t "
        "from pg_attribute a join pg_class c on c.oid = a.attrelid "
        "where c.relname in ('embeddings', 'retrieval_embeddings') "
        "and a.attname in ('embedding', 'embedding_half') "
        "and not a.attisdropped"
    ).fetchall()
    dims = {r["t"][r["t"].index("(") + 1 : -1] for r in rows}
    assert len(dims) == 1, f"dimension drift between vector columns: {rows}"


def test_key_is_subject_and_model(conn):
    row = conn.execute(
        "select a.attname from pg_index i "
        "join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey) "
        "where i.indrelid = 'retrieval_embeddings'::regclass and i.indisprimary"
    ).fetchall()
    assert {r["attname"] for r in row} == {"graph_id", "model_id"}


def test_every_active_model_has_a_partial_index(conn):
    """A single index over the whole table would mix vector spaces that are
    not comparable, and pgvector cannot tell them apart."""
    models = conn.execute(
        "select model_id from retrieval_models where active and kind = 'embedding'"
    ).fetchall()
    defs = conn.execute(
        "select indexdef from pg_indexes where tablename = 'retrieval_embeddings'"
    ).fetchall()
    hnsw = [d["indexdef"] for d in defs if "hnsw" in d["indexdef"]]
    for m in models:
        matching = [d for d in hnsw if f"'{m['model_id']}'" in d]
        assert matching, f"no partial HNSW index for {m['model_id']}"
        assert "halfvec_cosine_ops" in matching[0]


def test_reranker_gets_no_serving_index(conn):
    """Calling the helper over the whole registry must be safe, so a reranker
    returns quietly rather than raising."""
    conn.execute("select cg_register_retrieval_model('t-serve-rr', 'reranker', 'p', 'r', 'rev')")
    conn.execute("select cg_create_serving_index('t-serve-rr')")
    defs = conn.execute(
        "select indexdef from pg_indexes where tablename = 'retrieval_embeddings'"
    ).fetchall()
    assert not any("t-serve-rr" in d["indexdef"] for d in defs)


def test_unknown_model_raises(conn):
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("select cg_create_serving_index('no-such-model')")


def test_cold_subjects_are_absent(conn):
    """The index is small because the table is small. If cold subjects leaked
    in, the whole reason for the split would be gone."""
    row = conn.execute(
        "select count(*) as n from retrieval_embeddings re "
        "join embeddings e on e.graph_id = re.graph_id and e.model_id = re.model_id "
        "where not e.retrieval_active"
    ).fetchone()
    assert row["n"] == 0


def test_parity_measures_the_serving_tier(conn):
    """035 measured parity over `embeddings`; retrieval reads the serving
    tier, so that is what a gap has to be measured against."""
    definition = conn.execute(
        "select pg_get_viewdef('cg_retrieval_parity'::regclass) as d"
    ).fetchone()["d"]
    assert "retrieval_embeddings" in definition
