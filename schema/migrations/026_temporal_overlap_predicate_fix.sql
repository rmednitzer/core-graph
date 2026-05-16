-- 026_temporal_overlap_predicate_fix.sql
-- Fix a bitemporal-correctness defect in 020's ex_temporal_no_overlap.
--
-- 020 added two guards over (source_id, target_id, edge_label, fact_type):
--
--   uq_temporal_active_fact   UNIQUE ... WHERE t_invalid IS NULL
--                                          AND t_superseded IS NULL
--   ex_temporal_no_overlap    EXCLUDE (... valid_range WITH &&)   -- no WHERE
--
-- The exclusion constraint has NO partial predicate, so it applies to
-- every row including superseded/invalidated history. The core bitemporal
-- operation — superseding a fact in transaction time (set t_superseded)
-- while it remains valid in valid time — produces two rows with the same
-- key whose valid_range overlaps. ex_temporal_no_overlap rejects that
-- INSERT, making lawful supersession impossible and contradicting
-- uq_temporal_active_fact's own definition of "active".
--
-- Recreate the exclusion with the SAME partial predicate as the unique
-- index so "no overlap" is enforced only among currently-active facts.
--
-- Idempotent: guarded drop + guarded re-add via pg_constraint lookups
-- (PostgreSQL 16 has no ALTER ... ADD/DROP CONSTRAINT IF [NOT] EXISTS).

create extension if not exists btree_gist;

do $$
begin
    if exists (
        select 1 from pg_constraint
         where conname = 'ex_temporal_no_overlap'
           and conrelid = 'temporal_facts'::regclass
    ) then
        alter table temporal_facts drop constraint ex_temporal_no_overlap;
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'ex_temporal_no_overlap'
           and conrelid = 'temporal_facts'::regclass
    ) then
        alter table temporal_facts
            add constraint ex_temporal_no_overlap
            exclude using gist (
                source_id with =,
                target_id with =,
                edge_label with =,
                fact_type with =,
                valid_range with &&
            )
            where (t_invalid is null and t_superseded is null);
    end if;
end $$;
