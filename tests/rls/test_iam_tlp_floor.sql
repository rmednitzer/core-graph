-- test_iam_tlp_floor.sql
-- Verify that IAM vertices are not visible when app.max_tlp < 2.
-- The iam_tlp_floor policy must enforce TLP:AMBER as the minimum
-- visibility level for all IAM data, regardless of vertex tlp_level.

-- Setup: Insert a Principal vertex with tlp_level = 2
select set_config('app.max_tlp', '4', true);

select * from ag_catalog.cypher('core_graph', $$
    merge (p:Principal {canonical_key: 'test-iam-rls-principal'})
    on create set p.username = 'rls_test_user',
                  p.tlp_level = 2,
                  p.source = 'test'
    return id(p)
$$) as (id agtype);

-- Test 1: Session with max_tlp = 2 (AMBER) should see the Principal
select set_config('app.max_tlp', '2', true);

do $$
declare
    cnt int;
begin
    select count(*) into cnt
    from core_graph."Principal"
    where ((properties::text)::jsonb->>'canonical_key') = 'test-iam-rls-principal';

    if cnt = 0 then
        raise exception 'FAIL: Principal not visible at TLP:AMBER (max_tlp=2)';
    end if;
    raise notice 'PASS: Principal visible at TLP:AMBER';
end $$;

-- Test 2: Session with max_tlp = 1 (GREEN) must NOT see the Principal
select set_config('app.max_tlp', '1', true);

do $$
declare
    cnt int;
begin
    select count(*) into cnt
    from core_graph."Principal"
    where ((properties::text)::jsonb->>'canonical_key') = 'test-iam-rls-principal';

    if cnt > 0 then
        raise exception 'FAIL: Principal visible at TLP:GREEN (max_tlp=1) — IAM floor violated';
    end if;
    raise notice 'PASS: Principal not visible at TLP:GREEN (IAM floor enforced)';
end $$;

-- Test 3: Session with max_tlp = 0 (CLEAR) must NOT see the Principal
select set_config('app.max_tlp', '0', true);

do $$
declare
    cnt int;
begin
    select count(*) into cnt
    from core_graph."Principal"
    where ((properties::text)::jsonb->>'canonical_key') = 'test-iam-rls-principal';

    if cnt > 0 then
        raise exception 'FAIL: Principal visible at TLP:CLEAR (max_tlp=0) — IAM floor violated';
    end if;
    raise notice 'PASS: Principal not visible at TLP:CLEAR (IAM floor enforced)';
end $$;

-- Cleanup
select set_config('app.max_tlp', '4', true);
