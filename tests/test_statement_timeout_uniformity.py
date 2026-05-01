"""Verify statement_timeout is set uniformly across all DB callers.

Phase-0 audit found that statement_timeout was only set inside
`api/mcp/tools/cypher_query.py`. Other entry points (REST routes, ingest
workers, TAXII handlers, identity_attribution writer, vector search) all
acquired connections via `api.db.get_connection` but inherited no per-role
ceiling, leaving runaway query risk on those paths.

Fix: statement_timeout is now set inside `get_connection` itself based on
caller roles, so every caller gets the same enforcement.

This test reads the source and asserts the canonical site is in `api/db.py`
and that no other module performs its own redundant set_config of
statement_timeout (which would mask the central setting).
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_FILE = ROOT / "api" / "db.py"
PYTHON_DIRS = (ROOT / "api", ROOT / "ingest")


def test_get_connection_sets_statement_timeout() -> None:
    text = DB_FILE.read_text()
    assert "statement_timeout" in text, (
        "api/db.py must set statement_timeout uniformly inside get_connection."
    )
    assert "query_timeout_ms" in text, (
        "api/db.py must source the timeout from age_query_guard.query_timeout_ms."
    )


def test_no_other_module_sets_statement_timeout() -> None:
    """Reject duplicated statement_timeout writes outside api/db.py.

    Tests, runbooks, and migration files are explicitly allowed.
    """
    offenders: list[str] = []
    for root in PYTHON_DIRS:
        for path in root.rglob("*.py"):
            if path == DB_FILE:
                continue
            text = path.read_text()
            if "set_config('statement_timeout'" in text:
                offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, (
        "statement_timeout is set in modules other than api/db.py; "
        f"offenders: {offenders}. Centralise into api.db.get_connection()."
    )
