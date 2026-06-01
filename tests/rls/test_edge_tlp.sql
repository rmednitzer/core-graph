-- tests/rls/test_edge_tlp.sql
-- Phase 2/7 — verify edge tlp_level RLS, the writer's column maintenance, and
-- the re-classification cascade.
--
-- Run as a database superuser; the test temporarily switches to a non-superuser
-- role (cg_soc_analyst) to exercise RLS (a superuser bypasses it). Requires
-- migrations 001-032 applied to a core_graph database.
--
-- This test runs against the REAL `core_graph` graph and the production 022/032
-- machinery, because that machinery is intentionally scoped to core_graph
-- (cg_vertex_tlp_level reads core_graph._ag_label_vertex; cg_resync_vertex_edges
-- walks core_graph edge tables). An earlier version used an isolated AGE graph
-- and could never exercise them.
--
-- It also mirrors the real write path's quirk: AGE 1.7 executes Cypher through
-- its own executor and does NOT fire the per-table triggers, so a Cypher MERGE
-- leaves the denormalized edge tlp_level column at 0. ingest/graph_writer.py
-- therefore maintains the column with explicit SQL after each Cypher write —
-- a direct edge UPDATE on creation, and cg_resync_vertex_edges() after a vertex
-- MERGE for the cascade. This test drives exactly those two SQL paths. Both
-- assertions would FAIL (edge visible at every ceiling) if the column were left
-- at the Cypher-only default of 0.

\set ON_ERROR_STOP on

begin;

set search_path = ag_catalog, '$user', public;

-- ---------------------------------------------------------------------------
-- Seed (in core_graph): two TLP=3 Host vertices and one TLP=3 edge.
-- Capture the vertex/edge ids so we can drive the writer's SQL maintenance.
-- ---------------------------------------------------------------------------
select id_a, id_e
  from ag_catalog.cypher('core_graph', $$
      create (a:Host {canonical_key: 'edge-tlp-test-a', tlp_level: 3})
      create (b:Host {canonical_key: 'edge-tlp-test-b', tlp_level: 3})
      create (a)-[e:connects_to {source: 'edge-tlp-test', tlp_level: 3}]->(b)
      return id(a), id(e)
  $$) as (id_a agtype, id_e agtype)
\gset

-- A Cypher MERGE does not fire trg_edge_tlp_sync, so the column is still 0 here.
do $$
declare
    col smallint;
begin
    select tlp_level into col from core_graph.connects_to
     where (properties::text)::jsonb->>'source' = 'edge-tlp-test';
    if col <> 0 then
        raise notice 'edge_tlp_test note: column already %, AGE fired the trigger', col;
    end if;
end $$;

-- Writer edge-creation path: a plain SQL UPDATE on the new edge fires
-- trg_edge_tlp_sync, which sets tlp_level = GREATEST(property, src, dst) = 3.
update core_graph.connects_to set tlp_level = tlp_level
 where id = (:'id_e')::ag_catalog.graphid;

do $$
declare
    col smallint;
begin
    select tlp_level into col from core_graph.connects_to
     where (properties::text)::jsonb->>'source' = 'edge-tlp-test';
    if col <> 3 then
        raise exception 'edge_tlp_test FAIL: writer sync left edge tlp_level = % (expected 3)', col;
    end if;
    raise notice 'edge_tlp_test OK: writer SQL sync populated edge tlp_level = 3';
end $$;

-- cg_soc_analyst holds no schema USAGE by default (the app reads as the
-- cg_admin superuser); grant it plus SELECT on the edge table as setup so RLS,
-- not a missing privilege, is what filters rows.
grant usage on schema core_graph, ag_catalog to cg_soc_analyst;
grant select on core_graph.connects_to to cg_soc_analyst;

-- ---------------------------------------------------------------------------
-- Test 1: caller with max_tlp=2 cannot see the TLP=3 edge.
-- ---------------------------------------------------------------------------
do $$
declare
    visible_edges int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '2';
    select count(*) into visible_edges from core_graph.connects_to
     where (properties::text)::jsonb->>'source' = 'edge-tlp-test';
    if visible_edges <> 0 then
        raise exception 'edge_tlp_test FAIL: max_tlp=2 saw % TLP=3 edge(s)', visible_edges;
    end if;
    reset role;
    raise notice 'edge_tlp_test OK: max_tlp=2 caller sees zero TLP=3 edges';
end $$;

-- ---------------------------------------------------------------------------
-- Test 2: caller with max_tlp=3 sees the edge.
-- ---------------------------------------------------------------------------
do $$
declare
    visible_edges int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '3';
    select count(*) into visible_edges from core_graph.connects_to
     where (properties::text)::jsonb->>'source' = 'edge-tlp-test';
    if visible_edges <> 1 then
        raise exception 'edge_tlp_test FAIL: max_tlp=3 expected 1 edge, got %', visible_edges;
    end if;
    reset role;
    raise notice 'edge_tlp_test OK: max_tlp=3 caller sees the TLP=3 edge';
end $$;

-- ---------------------------------------------------------------------------
-- Test 3: cascade — re-classifying a vertex up updates incident edges.
-- ---------------------------------------------------------------------------
-- Re-classify vertex a 3 -> 4 via Cypher SET (the write path the app uses).
-- AGE will not fire trg_vertex_tlp_cascade for it, so the writer calls
-- cg_resync_vertex_edges() explicitly — do the same here.
select * from ag_catalog.cypher('core_graph', $$
    match (a:Host {canonical_key: 'edge-tlp-test-a'})
    set a.tlp_level = 4
$$) as (out agtype);

select cg_resync_vertex_edges((:'id_a')::ag_catalog.graphid);

do $$
declare
    col smallint;
    visible_edges int;
begin
    select tlp_level into col from core_graph.connects_to
     where (properties::text)::jsonb->>'source' = 'edge-tlp-test';
    if col <> 4 then
        raise exception 'edge_tlp_test FAIL: cascade left edge tlp_level = % (expected 4)', col;
    end if;

    set local role = cg_soc_analyst;
    set local app.max_tlp = '3';
    select count(*) into visible_edges from core_graph.connects_to
     where (properties::text)::jsonb->>'source' = 'edge-tlp-test';
    if visible_edges <> 0 then
        raise exception 'edge_tlp_test FAIL: cascade did not propagate, edge still visible at max_tlp=3 (count=%)', visible_edges;
    end if;
    reset role;
    raise notice 'edge_tlp_test OK: cascade ratcheted edge to 4 and hid it from max_tlp=3';
end $$;

rollback;

\echo 'edge_tlp tests: all PASSED'
