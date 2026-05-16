"""Static safety scan for migration 024_audit_log_integrity_hardening.sql.

Live-DB coverage (apply, insert, then verify_chain round trip) runs via
tests/schema/test_migrations.sh in CI. These parse-only checks pin the
three hardening properties so a future edit cannot silently drop them.
"""

from __future__ import annotations

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "migrations"
    / "024_audit_log_integrity_hardening.sql"
)


def _read() -> str:
    return MIGRATION_PATH.read_text()


def _read_no_comments() -> str:
    """Strip `-- ...` line comments so checks don't trip on the rationale."""
    out = []
    for line in _read().splitlines():
        idx = line.find("--")
        out.append(line if idx < 0 else line[:idx])
    return "\n".join(out)


def test_migration_present() -> None:
    assert MIGRATION_PATH.is_file()


def test_blocks_truncate() -> None:
    text = _read().lower()
    assert "before truncate on audit_log" in text
    assert "for each statement" in text
    assert "revoke truncate on audit_log from public" in text


def test_hash_chain_is_serialised() -> None:
    text = _read().lower()
    assert "pg_advisory_xact_lock" in text, (
        "Concurrent INSERTs must be serialised or the hash chain forks."
    )


def test_canonical_timestamp_encoding() -> None:
    text = _read()
    code = _read_no_comments()
    # Must hash a canonical UTC form, not the ambiguous `created_at::text`.
    assert "at time zone 'UTC'" in text
    assert 'YYYY-MM-DD"T"HH24:MI:SS"."US"Z"' in text
    assert "created_at::text" not in code.lower()


def test_field_separator_present() -> None:
    # 0x1E record separator framing prevents field-boundary-shift forgery.
    assert r"E'\x1e'" in _read()


def test_idempotent_constructs() -> None:
    text = _read().lower()
    assert "create or replace function audit_log_hash_chain()" in text
    assert "drop trigger if exists trg_audit_log_no_truncate on audit_log" in text
