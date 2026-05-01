\echo 'applying 020_temporal_invariants.sql'
-- 020_temporal_invariants.sql
-- Strengthen bitemporal invariants and append-only semantics for evidentiary facts.
-- Idempotent: every operation is wrapped in IF NOT EXISTS, DO blocks, or pg_catalog
-- existence checks. Safe to re-run.
--
-- Notes on ordering:
--   New required columns are added first, backfilled with sentinel values for any
--   existing rows, and only then promoted to NOT NULL. This keeps the migration
--   safe on tables that already contain data (CI/dev: empty; staging/prod: populated).
--
-- PostgreSQL 16 does not support `ADD CONSTRAINT IF NOT EXISTS`; conditional
-- constraint creation is implemented via pg_constraint catalog lookups inside
-- DO blocks.

-- ---------------------------------------------------------------------------
-- 1. Columns
-- ---------------------------------------------------------------------------

alter table temporal_facts
    add column if not exists mutation_actor text,
    add column if not exists mutation_reason text,
    add column if not exists superseded_by_fact_id bigint;

-- Backfill sentinel values for pre-existing rows (idempotent — only NULLs touched).
update temporal_facts
   set mutation_actor = 'system:pre-020-migration'
 where mutation_actor is null;

update temporal_facts
   set mutation_reason = 'backfilled-during-020-migration'
 where mutation_reason is null;

-- `source` was added in an earlier migration; cover the unlikely NULL case before
-- promoting to NOT NULL.
update temporal_facts
   set source = 'unknown:pre-020-migration'
 where source is null;

alter table temporal_facts
    alter column source set not null,
    alter column mutation_actor set not null,
    alter column mutation_reason set not null;

-- ---------------------------------------------------------------------------
-- 2. Constraints (PG 16 has no IF NOT EXISTS for ADD CONSTRAINT)
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'fk_temporal_superseded_by'
           and conrelid = 'temporal_facts'::regclass
    ) then
        alter table temporal_facts
            add constraint fk_temporal_superseded_by
            foreign key (superseded_by_fact_id) references temporal_facts(id);
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'chk_temporal_valid_window'
           and conrelid = 'temporal_facts'::regclass
    ) then
        alter table temporal_facts
            add constraint chk_temporal_valid_window
            check (t_invalid is null or t_valid <= t_invalid);
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'chk_temporal_recorded_window'
           and conrelid = 'temporal_facts'::regclass
    ) then
        alter table temporal_facts
            add constraint chk_temporal_recorded_window
            check (t_superseded is null or t_recorded <= t_superseded);
    end if;
end $$;

create unique index if not exists uq_temporal_active_fact
    on temporal_facts (source_id, target_id, edge_label, fact_type)
    where t_invalid is null and t_superseded is null;

create extension if not exists btree_gist;

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
            );
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Append-only delete protection
-- ---------------------------------------------------------------------------

create or replace function temporal_facts_block_delete()
returns trigger as $$
begin
    raise exception 'temporal_facts is append-only; use supersession via t_superseded/t_invalid';
end;
$$ language plpgsql;

drop trigger if exists trg_temporal_facts_no_delete on temporal_facts;
create trigger trg_temporal_facts_no_delete
    before delete on temporal_facts
    for each row execute function temporal_facts_block_delete();
