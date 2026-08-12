"""The serving pool actually enforces RLS (ADR-0014).

Migration 038 created `cg_app`; `tests/rls/test_application_role.sql` proved the
role is correct in isolation. This suite proves the other half: that the pool in
`api.db` is the thing connecting as it, so a request served through
`get_connection()` is filtered by the caller's clearance.

That distinction is the whole point. Every policy in this repository reads
`app.max_tlp`, and none of them binds for a superuser. Until the pool moved off
`cg_admin`, every one of them was decoration -- correct, tested, and never
evaluated for a single request.

Skipped when the stack is not reachable, matching tests/integration/conftest.py.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from api import db
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


# The conftest `_reset_state` autouse fixture opens the pool, so these tests do
# not manage its lifecycle themselves.


@pytest.mark.asyncio
async def test_pool_role_does_not_bypass_rls():
    """The regression this whole change exists to prevent.

    If this fails, every other RLS assertion in the repository is vacuous for
    the request path, and nothing else would notice: there is no error when a
    superuser reads through a policy, only more rows.
    """
    async with db.get_connection() as conn:
        row = await (
            await conn.execute(
                "select current_user as role, rolsuper, rolbypassrls "
                "  from pg_roles where rolname = current_user"
            )
        ).fetchone()

    assert row is not None
    assert not row["rolsuper"], (
        f"the serving pool is connected as {row['role']!r}, a superuser; "
        "superusers bypass row-level security unconditionally, so no TLP "
        "policy is evaluated for any request"
    )
    assert not row["rolbypassrls"], f"the serving pool role {row['role']!r} holds BYPASSRLS"


@pytest.mark.asyncio
async def test_owner_dsn_is_still_the_privileged_one():
    """The split is deliberate, not an accident of configuration.

    Migrations, the trusted writers and the evidence tooling keep the owner
    identity: they write at whatever TLP their source declares and must not be
    filtered by a caller's clearance. If both DSNs resolved to the same role the
    split would be silently gone -- in whichever direction.
    """
    with psycopg.connect(PG_DSN, row_factory=dict_row) as conn:
        owner = conn.execute("select current_user as role").fetchone()

    async with db.get_connection() as conn:
        app = await (await conn.execute("select current_user as role")).fetchone()

    assert owner is not None and app is not None
    assert owner["role"] != app["role"], (
        "CG_PG_APP_DSN and CG_PG_DSN resolve to the same role "
        f"({owner['role']!r}); the serving pool has fallen back to the owner"
    )


@pytest.mark.asyncio
async def test_clearance_filters_what_a_request_can_see():
    """End to end through the pool: the caller's ceiling decides the rows.

    Uses `embeddings` because 037 put a plain `tlp_level <= ceiling` policy on
    it, so the assertion is about enforcement rather than about the graph
    schema. Rows are written with the owner identity (as a real producer would)
    and read back through the pool.
    """
    dim = None
    with psycopg.connect(PG_DSN, row_factory=dict_row) as conn:
        dim = conn.execute(
            "select atttypmod as dim from pg_attribute "
            "where attrelid = 'embeddings'::regclass and attname = 'embedding'"
        ).fetchone()["dim"]
        conn.execute(
            "insert into embedding_models (model_id, dim) values ('t-appenf', %s) "
            "on conflict (model_id) do nothing",
            (dim,),
        )
        conn.execute(
            "insert into embeddings "
            "  (graph_id, label, content, model, model_id, tlp_level) "
            "values (-9300, 'AppEnf', 'clear', 't-appenf', 't-appenf', 0), "
            "       (-9301, 'AppEnf', 'amber', 't-appenf', 't-appenf', 2), "
            "       (-9304, 'AppEnf', 'red',   't-appenf', 't-appenf', 4)"
        )
        conn.commit()

    try:
        async with db.get_connection({"max_tlp": 2, "role": "soc_analyst"}) as conn:
            rows = await (
                await conn.execute(
                    "select graph_id from embeddings "
                    " where graph_id between -9304 and -9300 order by graph_id"
                )
            ).fetchall()

        seen = [r["graph_id"] for r in rows]
        assert seen == [-9301, -9300], (
            f"a caller cleared to TLP:2 saw {seen}; expected the TLP:0 and TLP:2 "
            "rows only, and never the TLP:4 row"
        )

        # And the ceiling has to actually move, or the assertion above could be
        # passing for some unrelated reason.
        async with db.get_connection({"max_tlp": 4, "role": "ciso"}) as conn:
            rows = await (
                await conn.execute(
                    "select graph_id from embeddings  where graph_id between -9304 and -9300"
                )
            ).fetchall()
        assert len(rows) == 3
    finally:
        with psycopg.connect(PG_DSN) as conn:
            conn.execute("delete from embeddings where graph_id between -9304 and -9300")
            conn.execute("delete from embedding_models where model_id = 't-appenf'")
            conn.commit()


@pytest.mark.asyncio
async def test_a_clearance_caller_runs_as_its_own_database_role():
    """ADR-0015. `tests/rls/test_clearance_roles.sql` proves the roles behave;
    this proves the pool actually assumes them for a request."""
    async with db.get_connection({"roles": ["soc_analyst"], "max_tlp": 2}) as conn:
        row = await (await conn.execute("select current_user as role")).fetchone()
    assert row is not None
    assert row["role"] == "cg_soc_analyst"


@pytest.mark.asyncio
async def test_the_role_does_not_leak_to_the_next_borrower():
    """The failure this design is shaped around. `SET LOCAL ROLE` reverts at
    transaction end, so a connection returned to the pool carrying a clearance
    would be a cross-caller leak with no error to notice it by."""
    async with db.get_connection({"roles": ["ciso"], "max_tlp": 4}) as conn:
        row = await (await conn.execute("select current_user as role")).fetchone()
        assert row is not None and row["role"] == "cg_ciso"

    # A fresh acquire, which may well be the same pooled connection.
    async with db.get_connection() as conn:
        row = await (await conn.execute("select current_user as role")).fetchone()
    assert row is not None
    assert row["role"] != "cg_ciso", "the clearance role survived into the next request"


@pytest.mark.asyncio
async def test_an_unmapped_caller_keeps_the_pool_role():
    """The synthetic dev identity emits `admin`, which is deliberately not a
    clearance. It must fall through rather than fail, and the fall-through is
    still non-superuser and still policy-bound."""
    async with db.get_connection({"roles": ["admin"], "max_tlp": 2}) as conn:
        row = await (
            await conn.execute(
                "select current_user as role, "
                "       rolsuper, rolbypassrls "
                "  from pg_roles where rolname = current_user"
            )
        ).fetchone()

    assert row is not None
    assert row["role"] not in {"cg_ciso", "cg_soc_analyst"}
    assert not row["rolsuper"] and not row["rolbypassrls"]


@pytest.mark.asyncio
async def test_the_append_only_audit_log_stays_append_only_for_the_pool():
    """038 carved UPDATE and DELETE out of the pool role's broad table grant.

    The evidence chain rests on the audit log being append-only, and the pool is
    the identity most likely to be reached by a request. INSERT stays, because
    every audited tool writes one.
    """
    async with db.get_connection() as conn:
        row = await (
            await conn.execute(
                "select has_table_privilege(current_user, 'audit_log', 'INSERT') as ins, "
                "       has_table_privilege(current_user, 'audit_log', 'UPDATE') as upd, "
                "       has_table_privilege(current_user, 'audit_log', 'DELETE') as del"
            )
        ).fetchone()

    assert row is not None
    assert row["ins"], "the pool role cannot write audit entries"
    assert not row["upd"], "the pool role can UPDATE audit_log; it is append-only"
    assert not row["del"], "the pool role can DELETE from audit_log; it is append-only"
