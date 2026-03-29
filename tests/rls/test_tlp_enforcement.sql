-- tests/rls/test_tlp_enforcement.sql
-- RLS enforcement test for TLP markings.
-- Creates test roles, inserts test data, verifies visibility per role,
-- then cleans up everything.

-- Helper: raise an exception with context if a condition is false.
-- Usage: PERFORM assert_eq(actual, expected, 'message');

-- ============================================================
-- Setup
-- ============================================================

-- Create a minimal table to carry TLP-marked test data.
-- In production the real graph nodes live in AGE / temporal tables;
-- here we use a lightweight stand-in to exercise RLS logic.

create table if not exists rls_test_nodes (
    id          serial primary key,
    label       text        not null,
    tlp_marking text        not null  -- CLEAR | GREEN | AMBER | RED
);

-- Enable RLS on the test table.
alter table rls_test_nodes enable row level security;
alter table rls_test_nodes force row level security;

-- ============================================================
-- Roles (seven-role hierarchy)
-- ============================================================

do $$
begin
    create role ciso_test           nologin;
    create role soc_analyst_test    nologin;
    create role compliance_officer_test nologin;
    create role it_operations_test  nologin;
    create role dpo_test            nologin;
    create role external_auditor_test nologin;
    create role ai_agent_test       nologin;
exception when duplicate_object then null;
end $$;

-- Grant table access to all roles so RLS is what limits visibility.
grant select on rls_test_nodes to
    ciso_test,
    soc_analyst_test,
    compliance_officer_test,
    it_operations_test,
    dpo_test,
    external_auditor_test,
    ai_agent_test;

-- ============================================================
-- RLS policies
-- ============================================================

drop policy if exists ciso_all              on rls_test_nodes;
drop policy if exists soc_analyst_pol       on rls_test_nodes;
drop policy if exists compliance_officer_pol on rls_test_nodes;
drop policy if exists it_operations_pol     on rls_test_nodes;
drop policy if exists dpo_no_access         on rls_test_nodes;
drop policy if exists external_auditor_pol  on rls_test_nodes;
drop policy if exists ai_agent_pol          on rls_test_nodes;

-- CISO sees everything
create policy ciso_all on rls_test_nodes
    for select to ciso_test using (true);

-- SOC analyst: CLEAR, GREEN, AMBER
create policy soc_analyst_pol on rls_test_nodes
    for select to soc_analyst_test
    using (tlp_marking in ('CLEAR', 'GREEN', 'AMBER'));

-- Compliance officer: CLEAR, GREEN
create policy compliance_officer_pol on rls_test_nodes
    for select to compliance_officer_test
    using (tlp_marking in ('CLEAR', 'GREEN'));

-- IT operations: CLEAR, GREEN
create policy it_operations_pol on rls_test_nodes
    for select to it_operations_test
    using (tlp_marking in ('CLEAR', 'GREEN'));

-- DPO: no access (empty using clause → never visible)
create policy dpo_no_access on rls_test_nodes
    for select to dpo_test
    using (false);

-- External auditor: CLEAR, GREEN
create policy external_auditor_pol on rls_test_nodes
    for select to external_auditor_test
    using (tlp_marking in ('CLEAR', 'GREEN'));

-- AI agent: CLEAR, GREEN (no PII-marked nodes handled by separate policy layer)
create policy ai_agent_pol on rls_test_nodes
    for select to ai_agent_test
    using (tlp_marking in ('CLEAR', 'GREEN'));

-- ============================================================
-- Seed test data
-- ============================================================

delete from rls_test_nodes;

insert into rls_test_nodes (label, tlp_marking) values
    ('node_clear',  'CLEAR'),
    ('node_green',  'GREEN'),
    ('node_amber',  'AMBER'),
    ('node_red',    'RED');

-- ============================================================
-- Assertion helper (runs as superuser)
-- ============================================================

do $$
declare
    v_count int;
begin
    -- ---- CISO: all four nodes visible ----
    set local role ciso_test;
    select count(*) into v_count from rls_test_nodes;
    if v_count <> 4 then
        raise exception 'FAIL ciso_test: expected 4 rows, got %', v_count;
    end if;
    reset role;

    -- ---- SOC analyst: CLEAR + GREEN + AMBER (3 rows) ----
    set local role soc_analyst_test;
    select count(*) into v_count from rls_test_nodes;
    if v_count <> 3 then
        raise exception 'FAIL soc_analyst_test: expected 3 rows, got %', v_count;
    end if;
    -- RED must not be visible
    select count(*) into v_count from rls_test_nodes where tlp_marking = 'RED';
    if v_count <> 0 then
        raise exception 'FAIL soc_analyst_test: RED row must not be visible';
    end if;
    reset role;

    -- ---- Compliance officer: CLEAR + GREEN (2 rows) ----
    set local role compliance_officer_test;
    select count(*) into v_count from rls_test_nodes;
    if v_count <> 2 then
        raise exception 'FAIL compliance_officer_test: expected 2 rows, got %', v_count;
    end if;
    reset role;

    -- ---- IT operations: CLEAR + GREEN (2 rows) ----
    set local role it_operations_test;
    select count(*) into v_count from rls_test_nodes;
    if v_count <> 2 then
        raise exception 'FAIL it_operations_test: expected 2 rows, got %', v_count;
    end if;
    reset role;

    -- ---- DPO: no rows ----
    set local role dpo_test;
    select count(*) into v_count from rls_test_nodes;
    if v_count <> 0 then
        raise exception 'FAIL dpo_test: expected 0 rows, got %', v_count;
    end if;
    reset role;

    -- ---- External auditor: CLEAR + GREEN (2 rows) ----
    set local role external_auditor_test;
    select count(*) into v_count from rls_test_nodes;
    if v_count <> 2 then
        raise exception 'FAIL external_auditor_test: expected 2 rows, got %', v_count;
    end if;
    reset role;

    -- ---- AI agent: CLEAR + GREEN (2 rows) ----
    set local role ai_agent_test;
    select count(*) into v_count from rls_test_nodes;
    if v_count <> 2 then
        raise exception 'FAIL ai_agent_test: expected 2 rows, got %', v_count;
    end if;
    reset role;

    raise notice 'All RLS assertions passed.';
end $$;

-- ============================================================
-- Cleanup
-- ============================================================

-- Drop the table (policies are dropped automatically with the table).
drop table if exists rls_test_nodes;

drop role if exists ciso_test;
drop role if exists soc_analyst_test;
drop role if exists compliance_officer_test;
drop role if exists it_operations_test;
drop role if exists dpo_test;
drop role if exists external_auditor_test;
drop role if exists ai_agent_test;
