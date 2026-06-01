-- test_iam_tlp_floor.sql
-- Verify the IAM TLP:AMBER read floor (migration 010): IAM vertices must be
-- invisible to any session with app.max_tlp < 2, regardless of the vertex's own
-- tlp_level. The Principal here is marked tlp_level = 1 (GREEN) on purpose so
-- that the standard tlp_read_policy alone (1 <= max_tlp) would admit it at
-- max_tlp = 1 — only the RESTRICTIVE iam_tlp_floor can hide it, which isolates
-- the floor from the ordinary TLP predicate.
--
-- Run as a database superuser; the test switches to the non-superuser
-- cg_soc_analyst role to exercise RLS (a superuser bypasses it). Requires
-- migrations 001-010 applied. Transactional — rolls back, leaves no rows.

\set ON_ERROR_STOP on

begin;

set search_path = ag_catalog, '$user', public;

-- Seed an IAM Principal marked GREEN (tlp_level = 1) as the superuser.
select set_config('app.max_tlp', '4', true);
select * from ag_catalog.cypher('core_graph', $$
    merge (p:Principal {canonical_key: 'test-iam-rls-principal'})
    set p.username = 'rls_test_user',
        p.tlp_level = 1,
        p.source = 'test'
    return id(p)
$$) as (id agtype);

-- cg_soc_analyst holds table SELECT on the IAM tables (migration 004/010) but
-- no schema USAGE (the app reads as the cg_admin superuser); grant it as setup
-- so RLS — not a missing privilege — is what hides rows.
grant usage on schema core_graph, ag_catalog to cg_soc_analyst;

-- ---------------------------------------------------------------------------
-- Test 1: max_tlp = 2 (AMBER) — floor satisfied, Principal visible.
-- ---------------------------------------------------------------------------
do $$
declare
    cnt int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '2';
    select count(*) into cnt
      from core_graph."Principal"
     where ((properties::text)::jsonb->>'canonical_key') = 'test-iam-rls-principal';
    reset role;
    if cnt = 0 then
        raise exception 'FAIL: Principal not visible at TLP:AMBER (max_tlp=2)';
    end if;
    raise notice 'PASS: Principal visible at TLP:AMBER';
end $$;

-- ---------------------------------------------------------------------------
-- Test 2: max_tlp = 1 (GREEN) — the floor must hide it even though the vertex
-- is itself GREEN (so the standard policy alone would admit it).
-- ---------------------------------------------------------------------------
do $$
declare
    cnt int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '1';
    select count(*) into cnt
      from core_graph."Principal"
     where ((properties::text)::jsonb->>'canonical_key') = 'test-iam-rls-principal';
    reset role;
    if cnt > 0 then
        raise exception 'FAIL: Principal visible at TLP:GREEN (max_tlp=1) — IAM floor violated';
    end if;
    raise notice 'PASS: Principal not visible at TLP:GREEN (IAM floor enforced)';
end $$;

-- ---------------------------------------------------------------------------
-- Test 3: max_tlp = 0 (CLEAR) — must not see the Principal.
-- ---------------------------------------------------------------------------
do $$
declare
    cnt int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '0';
    select count(*) into cnt
      from core_graph."Principal"
     where ((properties::text)::jsonb->>'canonical_key') = 'test-iam-rls-principal';
    reset role;
    if cnt > 0 then
        raise exception 'FAIL: Principal visible at TLP:CLEAR (max_tlp=0) — IAM floor violated';
    end if;
    raise notice 'PASS: Principal not visible at TLP:CLEAR (IAM floor enforced)';
end $$;

rollback;

\echo 'iam_tlp_floor tests: all PASSED'
