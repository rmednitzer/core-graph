-- test_stix_sdo_rls.sql
-- Verify migration 033: the completed STIX SDO labels (IntrusionSet, Identity,
-- Location, Report) enforce TLP at the engine, exactly like their Layer-1
-- siblings. Structural part: RLS enabled+forced and the full read/write policy
-- set attached. Behavioural part: a RED-marked Report is invisible to a
-- session cleared GREEN while a GREEN IntrusionSet stays visible, and the RED
-- row appears once the session is cleared RED.
--
-- Run as a database superuser; switches to the non-superuser cg_soc_analyst to
-- exercise RLS. Requires migrations 001-033 applied. Transactional — rolls
-- back, leaves no rows.

\set ON_ERROR_STOP on

begin;

set search_path = ag_catalog, '$user', public;

-- ---------------------------------------------------------------------------
-- Structural: RLS enabled + forced, policies present on all four new labels.
-- ---------------------------------------------------------------------------
do $$
declare
    lbl text;
    pol text;
begin
    foreach lbl in array array['IntrusionSet', 'Identity', 'Location', 'Report'] loop
        if not exists (
            select 1 from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'core_graph' and c.relname = lbl
               and c.relrowsecurity and c.relforcerowsecurity
        ) then
            raise exception 'FAIL: core_graph.% lacks enabled+forced RLS', lbl;
        end if;
        foreach pol in array array[
            'tlp_read_policy', 'ciso_full_access',
            'tlp_write_insert', 'tlp_write_update', 'tlp_write_delete',
            'ciso_full_write'
        ] loop
            if not exists (
                select 1 from pg_policies p
                 where p.schemaname = 'core_graph'
                   and p.tablename = lbl and p.policyname = pol
            ) then
                raise exception 'FAIL: core_graph.% lacks policy %', lbl, pol;
            end if;
        end loop;
    end loop;
    raise notice 'PASS: RLS enabled and policies attached on all four SDO labels';
end $$;

-- ---------------------------------------------------------------------------
-- Seed: a RED Report and a GREEN IntrusionSet, as the superuser.
-- ---------------------------------------------------------------------------
select set_config('app.max_tlp', '4', true);

select * from ag_catalog.cypher('core_graph', $$
    merge (r:Report {stix_id: 'report--rls-test-red'})
    set r.name = 'rls red report', r.tlp_level = 4
    return id(r)
$$) as (id agtype);

select * from ag_catalog.cypher('core_graph', $$
    merge (i:IntrusionSet {stix_id: 'intrusion-set--rls-test-green'})
    set i.name = 'rls green intrusion set', i.tlp_level = 1
    return id(i)
$$) as (id agtype);

-- cg_soc_analyst holds table SELECT (granted in 033) but no schema USAGE (the
-- app reads as the cg_admin superuser); grant it as setup so RLS — not a
-- missing privilege — is what hides rows.
grant usage on schema core_graph, ag_catalog to cg_soc_analyst;

-- ---------------------------------------------------------------------------
-- Test 1: max_tlp = 1 (GREEN) — RED Report hidden, GREEN IntrusionSet visible.
-- ---------------------------------------------------------------------------
do $$
declare
    cnt int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '1';
    select count(*) into cnt
      from core_graph."Report"
     where ((properties::text)::jsonb->>'stix_id') = 'report--rls-test-red';
    if cnt > 0 then
        reset role;
        raise exception 'FAIL: RED Report visible at TLP:GREEN (max_tlp=1)';
    end if;
    select count(*) into cnt
      from core_graph."IntrusionSet"
     where ((properties::text)::jsonb->>'stix_id') = 'intrusion-set--rls-test-green';
    reset role;
    if cnt = 0 then
        raise exception 'FAIL: GREEN IntrusionSet not visible at TLP:GREEN';
    end if;
    raise notice 'PASS: GREEN session sees GREEN IntrusionSet, not RED Report';
end $$;

-- ---------------------------------------------------------------------------
-- Test 2: max_tlp = 4 (RED) — the RED Report becomes visible.
-- ---------------------------------------------------------------------------
do $$
declare
    cnt int;
begin
    set local role = cg_soc_analyst;
    set local app.max_tlp = '4';
    select count(*) into cnt
      from core_graph."Report"
     where ((properties::text)::jsonb->>'stix_id') = 'report--rls-test-red';
    reset role;
    if cnt = 0 then
        raise exception 'FAIL: RED Report not visible at TLP:RED (max_tlp=4)';
    end if;
    raise notice 'PASS: RED session sees the RED Report';
end $$;

rollback;

\echo 'test_stix_sdo_rls.sql passed'
