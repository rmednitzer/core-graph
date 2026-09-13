"""Schema tests for the serving-role session limits (migration 043).

Requires a database with the migration chain applied; skipped when the stack
is not reachable, matching ``tests/schema/test_retention.py``.

Migration 043 moves ``statement_timeout`` and
``idle_in_transaction_session_timeout`` off the global server configuration
and onto the ``cg_app`` role, and creates ``pg_stat_statements``. The tests
read the role's stored settings and the extension catalog rather than opening
a session as ``cg_app``, because the role's password is deployment-specific
and ``api.db`` overrides ``statement_timeout`` per connection anyway.
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


def _role_settings(conn) -> dict[str, str]:
    row = conn.execute(
        "select coalesce(s.setconfig, '{}') as setconfig "
        "from pg_roles r left join pg_db_role_setting s "
        "on s.setrole = r.oid and s.setdatabase = 0 "
        "where r.rolname = 'cg_app'"
    ).fetchone()
    assert row is not None, "cg_app must exist (migration 038)"
    return dict(item.split("=", 1) for item in row["setconfig"])


def test_cg_app_carries_statement_timeout(conn):
    settings = _role_settings(conn)
    assert settings.get("statement_timeout") == "30s"


def test_cg_app_carries_idle_in_transaction_timeout(conn):
    settings = _role_settings(conn)
    assert settings.get("idle_in_transaction_session_timeout") == "60s"


def test_global_statement_timeout_is_not_set(conn):
    # The ceiling lives on the serving role, not on the cluster: the owner
    # identity that runs migrations and builds HNSW indexes must not be cut
    # off at 30s. reset_val is the server default, independent of what the
    # current session (or api.db) has set.
    row = conn.execute(
        "select reset_val from pg_settings where name = 'statement_timeout'"
    ).fetchone()
    assert row["reset_val"] == "0"


def test_pg_stat_statements_installed_and_preloaded(conn):
    row = conn.execute("select 1 from pg_extension where extname = 'pg_stat_statements'").fetchone()
    assert row is not None, "migration 043 creates pg_stat_statements"
    libs = conn.execute("show shared_preload_libraries").fetchone()
    assert "pg_stat_statements" in libs["shared_preload_libraries"]
    # Raises if the library is not preloaded, so this is the real check.
    conn.execute("select count(*) from pg_stat_statements")
