"""Static safety scan for migration 025_merkle_domain_separation.sql.

The SQL must stay byte-for-byte equivalent to evidence/chain/merkle.py;
the live-DB equivalence is asserted by tests/schema/test_migrations.sh.
"""

from __future__ import annotations

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "migrations"
    / "025_merkle_domain_separation.sql"
)


def _read() -> str:
    return MIGRATION_PATH.read_text()


def test_migration_present() -> None:
    assert MIGRATION_PATH.is_file()


def test_leaf_domain_separation() -> None:
    text = _read()
    # SQL escape-string literal carries a doubled backslash on disk.
    assert r"E'\\x00'::bytea || decode(entry_hash, 'hex')" in text


def test_internal_node_domain_separation() -> None:
    text = _read()
    assert r"E'\\x01'::bytea" in text


def test_odd_node_promoted_not_duplicated() -> None:
    text = _read().lower()
    # The lone-node branch must carry the node up unchanged...
    assert "promote" in text
    # ...and must NOT duplicate the last element like the old 016 did.
    assert "v_layer[array_length(v_layer, 1)]" not in text


def test_idempotent() -> None:
    text = _read().lower()
    assert "create or replace function compute_audit_merkle_root()" in text
