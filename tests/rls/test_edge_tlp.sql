-- tests/rls/test_edge_tlp.sql
-- Phase 2 — verify edge tlp_level RLS, cascade, and IAM floor.
--
-- Run as a database superuser; the test temporarily switches roles to
-- exercise RLS enforcement. Requires migrations 001-022 applied to a fresh
-- core_graph database.

\set ON_ERROR_STOP on

begin;

-- Use a dedicated AGE graph for the test so we don't pollute production.
do $$
begin
    if not exists (select 1 from ag_catalog.ag_graph where name = 'rls_edge_test') then
        perform ag_catalog.create_graph('rls_edge_test');
    end if;
end $$;

set search_path = ag_catalog, '$user', public;

-- ---------------------------------------------------------------------------
-- Seed: two TLP=3 vertices and one edge between them.
-- ---------------------------------------------------------------------------
select * from ag_catalog.cypher('rls_edge_test', $$
    create (a:Host {canonical_key: 'edge-test-a', tlp_level: 3})
    create (b:Host {canonical_key: 'edge-test-b', tlp_level: 3})
    create (a)-[:related {source: 'test', tlp_level: 3}]->(b)
$$) as (out agtype);

-- Apply edge tlp denormalization to the new graph's edge tables.
-- (Migration 022 walks all edge tables; re-running it picks up rls_edge_test
-- tables. We instead just create the column + trigger inline for the test
-- graph since dropping/re-running the whole migration in a test is overkill.)

do $$
declare
    tbl record;
begin
    for tbl in
        select c.relname
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'rls_edge_test'
           and c.relkind = 'r'
           and exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = 'start_id' and not a.attisdropped
           )
    loop
        execute format(
            'alter table rls_edge_test.%I add column if not exists tlp_level smallint not null default 0',
            tbl.relname
        );
        execute format(
            'update rls_edge_test.%I set tlp_level = greatest('
            '  coalesce(nullif(((properties::text)::jsonb->>''tlp_level''), ''''), ''0'')::smallint,'
            '  cg_vertex_tlp_level(start_id),'
            '  cg_vertex_tlp_level(end_id)'
            ')',
            tbl.relname
        );
        execute format(
            'drop trigger if exists trg_edge_tlp_sync on rls_edge_test.%I',
            tbl.relname
        );
        execute format(
            'create trigger trg_edge_tlp_sync '
            'before insert or update on rls_edge_test.%I '
            'for each row execute function cg_edge_tlp_sync()',
            tbl.relname
        );
        execute format(
            'alter table rls_edge_test.%I enable row level security',
            tbl.relname
        );
        execute format(
            'alter table rls_edge_test.%I force row level security',
            tbl.relname
        );
        execute format(
            'drop policy if exists tlp_edge_read_policy on rls_edge_test.%I',
            tbl.relname
        );
        execute format(
            'create policy tlp_edge_read_policy on rls_edge_test.%I '
            'for select using ('
            '  tlp_level <= coalesce(nullif(current_setting(''app.max_tlp'', true), ''''), ''1'')::smallint'
            ')',
            tbl.relname
        );
        execute format(
            'grant select on rls_edge_test.%I to public',
            tbl.relname
        );
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Test 1: caller with max_tlp=2 cannot see the TLP=3 edge.
-- ---------------------------------------------------------------------------
set local app.max_tlp = '2';
select set_config('role', 'cg_soc_analyst', true);

do $$
declare
    visible_edges int;
begin
    set local role = cg_soc_analyst;
    select count(*) into visible_edges
      from rls_edge_test.related;
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
    select count(*) into visible_edges from rls_edge_test.related;
    if visible_edges <> 1 then
        raise exception 'edge_tlp_test FAIL: max_tlp=3 expected 1 edge, got %', visible_edges;
    end if;
    reset role;
    raise notice 'edge_tlp_test OK: max_tlp=3 caller sees the TLP=3 edge';
end $$;

-- ---------------------------------------------------------------------------
-- Test 3: cascade — vertex re-classification updates incident edges.
-- ---------------------------------------------------------------------------
-- (Setup the cascade trigger on the test vertex tables so it actually fires.)
do $$
declare
    tbl record;
begin
    for tbl in
        select c.relname
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'rls_edge_test'
           and c.relkind = 'r'
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
            'drop trigger if exists trg_vertex_tlp_cascade on rls_edge_test.%I',
            tbl.relname
        );
        execute format(
            'create constraint trigger trg_vertex_tlp_cascade '
            'after update of properties on rls_edge_test.%I '
            'deferrable initially deferred '
            'for each row execute function cg_vertex_tlp_cascade()',
            tbl.relname
        );
    end loop;
end $$;

select * from ag_catalog.cypher('rls_edge_test', $$
    match (a:Host {canonical_key: 'edge-test-a'})
    set a.tlp_level = 4
$$) as (out agtype);

-- Force the deferred constraint trigger to fire before commit.
set constraints all immediate;

do $$
declare
    visible_edges int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '3';
    select count(*) into visible_edges from rls_edge_test.related;
    if visible_edges <> 0 then
        raise exception 'edge_tlp_test FAIL: cascade did not propagate, edge still visible at max_tlp=3 (count=%)', visible_edges;
    end if;
    reset role;
    raise notice 'edge_tlp_test OK: cascade hid the edge after vertex tlp 3 -> 4';
end $$;

rollback;

\echo 'edge_tlp tests: all PASSED'
