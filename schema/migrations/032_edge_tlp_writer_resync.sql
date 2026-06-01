\echo 'applying 032_edge_tlp_writer_resync.sql'
-- 032_edge_tlp_writer_resync.sql
-- Phase 7 — make the edge-TLP denormalization (022) effective against the
-- real, Cypher-driven write path.
--
-- Root cause this migration addresses:
--   Apache AGE 1.7 executes Cypher CREATE / MERGE / SET through its own
--   executor, which BYPASSES user-defined triggers on the label tables. The
--   BEFORE trigger `trg_edge_tlp_sync` (022) that maintains the denormalized
--   `tlp_level` column — and the `trg_vertex_tlp_cascade` AFTER trigger that
--   re-derives incident edges on re-classification — therefore NEVER fire for
--   graph writes performed via Cypher (i.e. every production write, since the
--   graph_writer and all skills write via ag_catalog.cypher()). The column was
--   left at its default 0, so `tlp_edge_read_policy` (which filters on the
--   column) admitted every edge regardless of marking: edge-level RLS was
--   effectively inert for Cypher-created edges.
--
--   A plain SQL UPDATE *does* fire the trigger (verified against AGE 1.7), so
--   the fix is to drive the existing trigger from SQL after each Cypher write
--   rather than rely on AGE to fire it. ingest/graph_writer.py now issues that
--   SQL UPDATE on the edge after every relationship MERGE, and calls
--   cg_resync_vertex_edges() (below) after every vertex MERGE so an upward
--   re-classification ratchets the incident edges.
--
-- This migration:
--   1. Adds cg_resync_vertex_edges(graphid) — a callable equivalent of the
--      trg_vertex_tlp_cascade trigger body, so the writer can invoke the
--      cascade explicitly (AGE will not fire the trigger for it).
--   2. Re-backfills tlp_level on every existing edge, repairing rows written
--      via Cypher between migration 022 and this fix (which are stuck at 0).
--
-- No RLS policy is changed or weakened: the read predicate stays exactly as
-- 022 defined it; this migration only makes the column it reads truthful.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Callable cascade: re-derive tlp_level for every edge incident to a vertex.
-- ---------------------------------------------------------------------------
--
-- Mirrors trg_vertex_tlp_cascade's body but as an ordinary function the writer
-- can SELECT after a Cypher vertex SET (which would not fire the trigger). The
-- no-op UPDATE re-fires each edge's BEFORE trigger (trg_edge_tlp_sync), which
-- recomputes tlp_level from the now-current endpoint TLPs. SECURITY DEFINER so
-- it can touch the AGE-internal edge tables irrespective of the caller's RLS.

create or replace function cg_resync_vertex_edges(p_vertex_id ag_catalog.graphid)
returns void as $$
declare
    tbl record;
begin
    -- Fast path: a freshly-merged vertex with no incident edges (the common
    -- case on the ingest hot path) costs a single indexed probe against the
    -- inheritance root and returns without walking the per-label edge tables.
    if not exists (
        select 1 from core_graph._ag_label_edge
         where start_id = p_vertex_id or end_id = p_vertex_id
    ) then
        return;
    end if;

    for tbl in
        select c.relname
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'core_graph'
           and c.relkind = 'r'
           and c.relname <> '_ag_label_edge'
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'start_id' and not a.attisdropped
           )
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'end_id' and not a.attisdropped
           )
           -- Only edge tables that use the 022 denormalized column. Some edge
           -- labels (e.g. the 023 memory-layer belongs_to) predate/skip 022 and
           -- enforce TLP via a properties-based policy instead — they have no
           -- tlp_level column to resync.
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'tlp_level' and not a.attisdropped
           )
    loop
        execute format(
            'update core_graph.%I set tlp_level = tlp_level '
            'where start_id = $1 or end_id = $1',
            tbl.relname
        ) using p_vertex_id;
    end loop;
end;
$$ language plpgsql security definer;

-- ---------------------------------------------------------------------------
-- 2. Re-backfill existing edges (repair Cypher-created rows stuck at tlp 0).
-- ---------------------------------------------------------------------------
--
-- Same derivation as the 022 backfill — GREATEST of any explicit properties
-- value and both endpoint vertex TLPs. Edges written before this migration via
-- Cypher never had the column maintained, so re-derive them all now.

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
           and c.relname <> '_ag_label_edge'
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'start_id' and not a.attisdropped
           )
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'end_id' and not a.attisdropped
           )
           -- Only tables 022 already gave a tlp_level column.
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'tlp_level' and not a.attisdropped
           )
    loop
        execute format($q$
            update core_graph.%I e
               set tlp_level = greatest(
                       coalesce(nullif(((e.properties::text)::jsonb->>'tlp_level'), ''), '0')::smallint,
                       cg_vertex_tlp_level(e.start_id),
                       cg_vertex_tlp_level(e.end_id)
                   )
             where tlp_level is distinct from greatest(
                       coalesce(nullif(((e.properties::text)::jsonb->>'tlp_level'), ''), '0')::smallint,
                       cg_vertex_tlp_level(e.start_id),
                       cg_vertex_tlp_level(e.end_id)
                   )
        $q$, tbl.relname);
    end loop;
end $$;
