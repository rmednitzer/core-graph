-- 031_uuidv7_audit_correlation.sql
-- PostgreSQL 18 modernization: time-ordered UUIDs for audit correlation.
--
-- Workstream-3 note (temporal constraints). The modernization audit evaluated
-- replacing the bitemporal trigger/exclusion invariants with PG18 native
-- WITHOUT OVERLAPS constraints and found them INAPPLICABLE here: WITHOUT
-- OVERLAPS is a non-partial PRIMARY KEY / UNIQUE constraint, but temporal_facts
-- requires *partial* non-overlap — enforced only among active facts — so that
-- superseding a fact (setting t_superseded while it is still valid) may create
-- legitimately overlapping history. Migration 026 added exactly that partial
-- predicate to ex_temporal_no_overlap; a native WITHOUT OVERLAPS constraint
-- (which cannot carry a WHERE clause) would re-introduce the 026 bug. The
-- partial EXCLUDE is therefore retained as the correct mechanism. See ADR-0007.
--
-- The fitting PG18 adoption for this area is uuidv7(): audit_log.correlation_id
-- was app-generated (uuid4, random) and left NULL when absent. Defaulting it to
-- uuidv7() gives time-ordered identifiers — better B-tree locality on
-- idx_audit_correlation and a natural temporal sort — for any audit row written
-- without an explicit correlation_id. The graph writer still supplies its own
-- per-message correlation_id, so this only changes the otherwise-NULL case.
--
-- Idempotent. Guarded so a pre-18 PostgreSQL (no uuidv7) cannot break the chain.

do $$
begin
    alter table audit_log alter column correlation_id set default uuidv7();
    raise notice 'audit_log.correlation_id now defaults to uuidv7() (time-ordered)';
exception
    when undefined_function then
        raise notice 'uuidv7() unavailable (PostgreSQL < 18); correlation_id default left unset';
end $$;
