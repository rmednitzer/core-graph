-- 024_audit_log_integrity_hardening.sql
-- Close three concrete tamper-evidence gaps in the audit log:
--
--   1. TRUNCATE bypass — 008's BEFORE UPDATE/DELETE row triggers do not
--      fire on TRUNCATE, so the entire append-only evidence log could be
--      wiped without tripping the immutability guard. Add a statement-level
--      BEFORE TRUNCATE trigger and REVOKE TRUNCATE.
--
--   2. Hash-chain fork race — 005's trigger reads the previous entry_hash
--      with no lock, so two concurrent INSERTs (READ COMMITTED) read the
--      same prev hash and produce a forked chain. Serialise chain
--      extension with a transaction-scoped advisory lock.
--
--   3. Serialisation mismatch — 005 hashed `new.created_at::text`
--      (timestamptz text rendering, e.g. `+00`, variable fractional
--      digits), which can never equal the Python verifier's
--      `str(datetime)` (`+00:00`). The chain was therefore unverifiable.
--      Hash a canonical UTC ISO-8601 form with 6-digit microseconds and a
--      0x1E field separator (prevents field-boundary-shift forgery), and
--      mirror it exactly in evidence/chain/verify.py.
--
-- This redefines audit_log_hash_chain() so the on-disk hash format changes.
-- That is intentional and safe pre-production: the previous format was
-- provably unverifiable (gap 3), so there is no valid historical chain to
-- preserve. Re-stamp/re-baseline after applying.
--
-- Idempotent: CREATE OR REPLACE, DROP TRIGGER IF EXISTS, guarded REVOKE.

-- ---------------------------------------------------------------------------
-- 1. Block TRUNCATE (statement-level; row triggers never fire on TRUNCATE)
-- ---------------------------------------------------------------------------

drop trigger if exists trg_audit_log_no_truncate on audit_log;
create trigger trg_audit_log_no_truncate
    before truncate on audit_log
    for each statement
    execute function audit_log_immutable();

revoke truncate on audit_log from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'cg_audit_writer') then
        execute 'revoke truncate on audit_log from cg_audit_writer';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- 2. Hash-chain trigger: serialise + canonical encoding
-- ---------------------------------------------------------------------------

create or replace function audit_log_hash_chain()
returns trigger as $$
declare
    prev_hash text;
begin
    -- Serialise chain extension: concurrent INSERTs must not read the same
    -- predecessor and fork the chain. Transaction-scoped so it releases on
    -- commit/rollback.
    perform pg_advisory_xact_lock(hashtext('core_graph.audit_log.hash_chain')::bigint);

    select entry_hash into prev_hash
    from audit_log
    order by id desc
    limit 1;

    new.prev_entry_hash := coalesce(prev_hash, 'genesis');

    -- Canonical, delimiter-framed payload. Every field is coalesced to a
    -- non-NULL text value and joined with U+001E (record separator), which
    -- the verifier reproduces byte-for-byte. created_at is rendered as
    -- UTC ISO-8601 with fixed 6-digit microseconds so PostgreSQL and
    -- Python agree regardless of session TimeZone.
    new.entry_hash := encode(digest(
        coalesce(new.entity_id::text, '')      || E'\x1e' ||
        coalesce(new.entity_label, '')         || E'\x1e' ||
        new.operation                          || E'\x1e' ||
        coalesce(new.old_value_hash, '')       || E'\x1e' ||
        coalesce(new.new_value_hash, '')       || E'\x1e' ||
        new.actor                              || E'\x1e' ||
        coalesce(new.correlation_id::text, '') || E'\x1e' ||
        new.prev_entry_hash                    || E'\x1e' ||
        to_char(new.created_at at time zone 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS"."US"Z"'),
        'sha256'
    ), 'hex');

    return new;
end;
$$ language plpgsql;

drop trigger if exists trg_audit_log_hash_chain on audit_log;
create trigger trg_audit_log_hash_chain
    before insert on audit_log
    for each row
    execute function audit_log_hash_chain();
