\echo 'applying 022_edge_tlp_denormalization.sql'
-- 022_edge_tlp_denormalization.sql
-- Phase 2 — close the documented edge-level RLS gap.
--
-- The AGE storage model gives every relationship type its own table that
-- inherits from `core_graph._ag_label_edge`. Each row has start_id, end_id,
-- and a `properties` agtype column. Until now edge tables either had no
-- TLP filter at all or relied on a JSONB lookup against `properties`,
-- which (a) is slow on hot paths and (b) yields TLP=GREEN for any edge
-- whose properties never had `tlp_level` set — a violation of "an edge
-- between two RED vertices should be RED".
--
-- Fix: add a real `tlp_level smallint` column to every edge label table,
-- backfill from endpoints (GREATEST of source/target vertex TLPs),
-- enforce range with CHECK, and re-derive on every INSERT/UPDATE via a
-- BEFORE trigger. RLS policy filters on the column directly.
--
-- IAM-layer edges keep their existing RESTRICTIVE TLP:AMBER floor from
-- migration 010 — this migration adds the standard tlp_read_policy on
-- top, never weakens the floor.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Helpers
-- ---------------------------------------------------------------------------

-- Read a vertex's tlp_level from its `properties` JSON. SECURITY DEFINER so
-- triggers running on edge tables can read vertex tables even when RLS would
-- otherwise filter the rows from the trigger's perspective.
create or replace function cg_vertex_tlp_level(vertex_id ag_catalog.graphid)
returns smallint as $$
declare
    tlp smallint;
begin
    select coalesce(((properties::text)::jsonb->>'tlp_level')::int, 0)::smallint
      into tlp
      from core_graph._ag_label_vertex
     where id = vertex_id;
    return coalesce(tlp, 0);
end;
$$ language plpgsql stable security definer;

-- Single trigger function reused across all edge tables.
create or replace function cg_edge_tlp_sync()
returns trigger as $$
declare
    src smallint;
    dst smallint;
    explicit smallint;
begin
    src := cg_vertex_tlp_level(new.start_id);
    dst := cg_vertex_tlp_level(new.end_id);
    explicit := nullif(((new.properties::text)::jsonb->>'tlp_level'), '')::smallint;
    -- Edge tlp_level is the strictest of: caller-supplied properties value,
    -- source vertex tlp, target vertex tlp. This matches the contract
    -- "an edge is at least as restricted as either endpoint".
    new.tlp_level := greatest(coalesce(explicit, 0), src, dst);
    if new.tlp_level < 0 or new.tlp_level > 4 then
        raise exception 'edge tlp_level out of range: %', new.tlp_level;
    end if;
    return new;
end;
$$ language plpgsql;

-- ---------------------------------------------------------------------------
-- 2. Walk every edge label table; install column, CHECK, trigger, policy.
-- ---------------------------------------------------------------------------

do $$
declare
    tbl record;
    iam_edges constant text[] := array['has_role','grants','actor_in','manages','owns','member_of'];
begin
    for tbl in
        select c.relname
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'core_graph'
           and c.relkind = 'r'
           and c.relname not in ('_ag_label_vertex', '_ag_label_edge')
           -- Edge tables expose start_id and end_id columns.
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid
                  and a.attname = 'start_id'
                  and not a.attisdropped
           )
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid
                  and a.attname = 'end_id'
                  and not a.attisdropped
           )
    loop
        -- Add column (default 0 so existing rows get a safe placeholder).
        execute format(
            'alter table core_graph.%I add column if not exists tlp_level smallint not null default 0',
            tbl.relname
        );

        -- Backfill from endpoints + any explicit properties value.
        execute format($q$
            update core_graph.%I e
               set tlp_level = greatest(
                       coalesce(nullif(((e.properties::text)::jsonb->>'tlp_level'), ''), '0')::smallint,
                       cg_vertex_tlp_level(e.start_id),
                       cg_vertex_tlp_level(e.end_id)
                   )
        $q$, tbl.relname);

        -- CHECK constraint via pg_constraint guard.
        execute format($q$
            do $g$ begin
                if not exists (
                    select 1 from pg_constraint
                     where conname = 'chk_%s_tlp_range'
                       and conrelid = 'core_graph.%I'::regclass
                ) then
                    alter table core_graph.%I
                        add constraint chk_%s_tlp_range
                        check (tlp_level between 0 and 4);
                end if;
            end $g$;
        $q$, tbl.relname, tbl.relname, tbl.relname, tbl.relname);

        -- BEFORE INSERT/UPDATE trigger to recompute tlp_level.
        execute format(
            'drop trigger if exists trg_edge_tlp_sync on core_graph.%I',
            tbl.relname
        );
        execute format(
            'create trigger trg_edge_tlp_sync '
            'before insert or update on core_graph.%I '
            'for each row execute function cg_edge_tlp_sync()',
            tbl.relname
        );

        -- Standard tlp_read_policy mirroring vertex RLS — uses the new column.
        execute format(
            'alter table core_graph.%I enable row level security',
            tbl.relname
        );
        execute format(
            'alter table core_graph.%I force row level security',
            tbl.relname
        );
        execute format(
            'drop policy if exists tlp_edge_read_policy on core_graph.%I',
            tbl.relname
        );
        execute format(
            'create policy tlp_edge_read_policy on core_graph.%I '
            'for select using ('
            '  tlp_level <= coalesce(nullif(current_setting(''app.max_tlp'', true), ''''), ''1'')::smallint'
            ')',
            tbl.relname
        );

        -- CISO unrestricted (idempotent — keep parity with 010 / 004).
        execute format(
            'drop policy if exists ciso_full_access on core_graph.%I',
            tbl.relname
        );
        execute format(
            'create policy ciso_full_access on core_graph.%I '
            'for select to cg_ciso using (true)',
            tbl.relname
        );

        -- Re-assert the IAM RESTRICTIVE floor for IAM edges, not weakened.
        if tbl.relname = any (iam_edges) then
            execute format(
                'drop policy if exists iam_tlp_floor on core_graph.%I',
                tbl.relname
            );
            execute format(
                'create policy iam_tlp_floor on core_graph.%I '
                'as restrictive for select using ('
                '  coalesce(nullif(current_setting(''app.max_tlp'', true), ''''), ''1'')::int >= 2'
                ')',
                tbl.relname
            );
        end if;

        -- Index on (tlp_level) speeds up the RLS predicate at scale.
        execute format(
            'create index if not exists idx_%s_tlp_level on core_graph.%I (tlp_level)',
            tbl.relname, tbl.relname
        );
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Cascade: vertex tlp_level change → recompute incident edges.
-- ---------------------------------------------------------------------------
--
-- When a vertex's properties.tlp_level changes (e.g. re-classification by an
-- analyst) any edge whose endpoint is that vertex must be re-evaluated. The
-- cascade trigger iterates edge tables and runs a no-op UPDATE that re-fires
-- each edge's BEFORE trigger to recompute tlp_level from the (now-changed)
-- endpoints. Implemented as a regular AFTER trigger (not a CONSTRAINT
-- TRIGGER) — re-classification is rare enough that batching to commit time
-- via DEFERRABLE is unnecessary, and CONSTRAINT TRIGGER on AGE-internal
-- tables exhibited a portability quirk in CI.

create or replace function cg_vertex_tlp_cascade()
returns trigger as $$
declare
    new_tlp smallint;
    old_tlp smallint;
    tbl record;
begin
    new_tlp := coalesce(((new.properties::text)::jsonb->>'tlp_level')::int, 0)::smallint;
    old_tlp := coalesce(((old.properties::text)::jsonb->>'tlp_level')::int, 0)::smallint;
    if new_tlp = old_tlp then
        return null;
    end if;

    for tbl in
        select c.relname
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'core_graph'
           and c.relkind = 'r'
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'start_id' and not a.attisdropped
           )
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'end_id' and not a.attisdropped
           )
    loop
        -- A no-op UPDATE re-fires the per-edge BEFORE trigger, which
        -- recomputes tlp_level from the (now-changed) endpoint.
        execute format(
            'update core_graph.%I set tlp_level = tlp_level '
            'where start_id = $1 or end_id = $1',
            tbl.relname
        ) using new.id;
    end loop;
    return null;
end;
$$ language plpgsql security definer;

-- Apply cascade trigger to every vertex label table.
do $$
declare
    tbl record;
begin
    for tbl in
        select c.relname
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'core_graph'
           and c.relkind = 'r'
           and c.relname not in ('_ag_label_vertex', '_ag_label_edge')
           -- Vertex tables have no start_id/end_id; just an `id` and `properties`.
           and not exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'start_id' and not a.attisdropped
           )
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'properties' and not a.attisdropped
           )
    loop
        execute format(
            'drop trigger if exists trg_vertex_tlp_cascade on core_graph.%I',
            tbl.relname
        );
        execute format(
            'create trigger trg_vertex_tlp_cascade '
            'after update of properties on core_graph.%I '
            'for each row execute function cg_vertex_tlp_cascade()',
            tbl.relname
        );
    end loop;
end $$;
