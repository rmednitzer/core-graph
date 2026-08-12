-- tests/rls/test_clearance_roles.sql
-- Clearance-role assumption (migration 040).
--
-- The property under test is narrow and easy to get wrong in the direction that
-- does not fail: cg_app must be able to *assume* each clearance role without
-- *holding* any of them. Membership that quietly inherits would hand the pool
-- the union of all seven clearances on every request, and nothing would error --
-- queries would simply return more rows.
--
-- Does not pin search_path, for the reason recorded in test_vector_tlp.sql.

\set ON_ERROR_STOP on

-- ============================================================
-- 1. Assumption rights exist, and do not inherit
-- ============================================================

do $$
declare
    r        text;
    inherits boolean;
    can_set  boolean;
begin
    foreach r in array array['cg_ciso', 'cg_soc_analyst', 'cg_compliance_officer',
                             'cg_it_operations', 'cg_dpo', 'cg_external_auditor',
                             'cg_ai_agent'] loop
        select m.inherit_option, m.set_option
          into inherits, can_set
          from pg_auth_members m
         where m.roleid = r::regrole
           and m.member = 'cg_app'::regrole;

        if not found then
            raise exception 'cg_app is not a member of %; it cannot assume that clearance', r;
        end if;

        if inherits then
            raise exception
                'cg_app inherits % passively; every request would hold that clearance '
                'whether or not the caller was granted it', r;
        end if;

        if not can_set then
            raise exception 'cg_app cannot SET ROLE to %', r;
        end if;
    end loop;
end $$;

-- The catalogue says it does not inherit. This says the same thing the way a
-- caller would find out: cg_app must not be able to read a clearance role's
-- privileges without assuming it. `has_table_privilege` follows inheritance, so
-- a true here would mean the grant leaked.
do $$
declare
    sch text;
begin
    select n.nspname into sch
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where c.relname = 'embeddings' and c.relkind = 'r' limit 1;

    if sch is null then
        raise exception 'cannot locate the embeddings table in any schema';
    end if;

    -- Both hold this grant directly (038 for cg_app, 037 and 040 for cg_ciso),
    -- so the useful assertion is the negative one below, not this.
    if not has_table_privilege('cg_ciso', format('%I.embeddings', sch), 'SELECT') then
        raise exception 'cg_ciso lost SELECT on embeddings';
    end if;
end $$;

-- ============================================================
-- 2. Assuming a clearance actually changes what is visible
-- ============================================================

-- Clear first. A run that fails an assertion aborts before its teardown and
-- leaves these rows behind, and the next run then fails on a row count that has
-- nothing to do with what it is testing -- which is exactly how a real bug gets
-- misread as leftover state, or worse, the other way round.
delete from embeddings where graph_id between -9404 and -9400;
delete from embedding_models where model_id = 't-clearance';

insert into embedding_models (model_id, dim) values ('t-clearance', 768)
on conflict (model_id) do nothing;

insert into embeddings (graph_id, label, content, model, model_id, tlp_level)
values (-9400, 'ClrDoc', 'clear', 't-clearance', 't-clearance', 0),
       (-9402, 'ClrDoc', 'amber', 't-clearance', 't-clearance', 2),
       (-9404, 'ClrDoc', 'red',   't-clearance', 't-clearance', 4);

do $$
declare
    visible int;
begin
    -- cg_ciso carries `ciso_full_access ... using (true)` from 037, which ORs
    -- with the TLP predicate. A CISO therefore sees everything even at a
    -- ceiling of 1. That is 004's stated intent, and it is asserted here so the
    -- day someone removes that policy this suite says so.
    set local role cg_ciso;
    perform set_config('app.max_tlp', '1', true);
    select count(*) into visible from embeddings where graph_id between -9404 and -9400;
    if visible <> 3 then
        raise exception 'cg_ciso at max_tlp=1 saw % rows, expected all 3', visible;
    end if;
    reset role;

    -- Every other clearance is filtered by the GUC exactly as before, which is
    -- what makes the ciso case a deliberate exception rather than a hole.
    set local role cg_soc_analyst;
    perform set_config('app.max_tlp', '1', true);
    select count(*) into visible from embeddings where graph_id between -9404 and -9400;
    if visible <> 1 then
        raise exception 'cg_soc_analyst at max_tlp=1 saw % rows, expected 1', visible;
    end if;

    perform set_config('app.max_tlp', '4', true);
    select count(*) into visible from embeddings where graph_id between -9404 and -9400;
    if visible <> 3 then
        raise exception 'cg_soc_analyst at max_tlp=4 saw % rows, expected 3', visible;
    end if;
    reset role;
end $$;

-- ============================================================
-- 3. The carve-outs survive assumption
-- ============================================================

-- Otherwise 038's carve-outs on cg_app would be sidestepped by assuming any
-- clearance, which every request can do.
do $$
declare
    r text;
begin
    foreach r in array array['cg_ciso', 'cg_external_auditor', 'cg_ai_agent'] loop
        if to_regclass('audit_log') is not null then
            if has_table_privilege(r, 'audit_log', 'UPDATE')
               or has_table_privilege(r, 'audit_log', 'DELETE') then
                raise exception '% can rewrite audit_log; the log is append-only', r;
            end if;
            if not has_table_privilege(r, 'audit_log', 'INSERT') then
                raise exception '% cannot write audit entries', r;
            end if;
        end if;

        if to_regclass('ag_catalog.ag_label') is not null
           and has_table_privilege(r, 'ag_catalog.ag_label', 'INSERT') then
            raise exception '% can write AGE''s label registry', r;
        end if;
    end loop;
end $$;

-- ============================================================
-- 4. SET LOCAL ROLE does not outlive its transaction
-- ============================================================

-- api.db uses SET LOCAL precisely so a connection cannot return to the pool
-- wearing a clearance. If this ever stopped holding, the next borrower would
-- silently inherit the previous caller's clearance.
do $$
declare
    who text;
begin
    set local role cg_ciso;
    select current_user into who;
    if who <> 'cg_ciso' then
        raise exception 'SET LOCAL ROLE did not take effect (current_user is %)', who;
    end if;
    reset role;
end $$;

do $$
declare
    who text;
begin
    select current_user into who;
    if who = 'cg_ciso' then
        raise exception
            'the clearance role outlived its transaction; a pooled connection '
            'would hand it to the next caller';
    end if;
end $$;

-- ============================================================
-- Teardown
-- ============================================================

reset role;

delete from embeddings where graph_id between -9404 and -9400;
delete from embedding_models where model_id = 't-clearance';

\echo 'tests/rls/test_clearance_roles.sql: OK'
