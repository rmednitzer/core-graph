-- tests/rls/test_application_role.sql
-- The application role created by migration 038.
--
-- Every other suite in tests/rls/ creates its own throwaway non-superuser role
-- and SET ROLEs to it. That proves the policies are correct. It does not prove
-- that anything the application actually connects as ever reaches them, and
-- until 038 nothing did: the cg_* roles from 004, 005 and 010 are NOLOGIN, and
-- the deployment connects as cg_admin, which is POSTGRES_USER in the official
-- postgres image and therefore a superuser. Superusers bypass row-level
-- security unconditionally.
--
-- So this suite asserts the property the others assume. It uses no role of its
-- own, and grants itself nothing: everything it exercises has to come from
-- migration 038, or the assertion fails.
--
-- Does not pin search_path, for the reason recorded in test_vector_tlp.sql:
-- the real vector tables live in ag_catalog, not public.

\set ON_ERROR_STOP on

-- ============================================================
-- 1. Role attributes
-- ============================================================

do $$
declare
    r record;
begin
    select rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole
      into r
      from pg_roles
     where rolname = 'cg_app';

    if not found then
        raise exception 'cg_app does not exist; migration 038 did not apply';
    end if;

    -- The one attribute this whole migration exists to guarantee. Either of
    -- these being true silently reinstates the gap: every policy in the
    -- repository stops being evaluated, and no test but this one notices.
    if r.rolsuper then
        raise exception 'cg_app is a superuser; RLS would be bypassed';
    end if;
    if r.rolbypassrls then
        raise exception 'cg_app has BYPASSRLS; RLS would be bypassed';
    end if;

    -- A role that cannot log in is a grant target, not a connection identity,
    -- which is exactly what the cg_* roles already were.
    if not r.rolcanlogin then
        raise exception 'cg_app cannot log in; it is unusable as an application role';
    end if;

    if r.rolcreatedb or r.rolcreaterole then
        raise exception 'cg_app holds CREATEDB or CREATEROLE';
    end if;
end $$;

-- ============================================================
-- 2. RLS is enforced for cg_app on the vector tier
-- ============================================================

-- The assertion that matters. 037 put a policy on `embeddings`; this shows the
-- policy binds for the role the application will connect as, using only the
-- grants 038 hands out.

-- `embeddings.model_id` has a foreign key onto the registry (021), so the
-- model has to exist first. The serving tier is not involved: this suite is
-- about the role, and test_vector_tlp.sql already covers retrieval_embeddings.
insert into embedding_models (model_id, dim) values ('cgapp-model', 768)
on conflict (model_id) do nothing;

insert into embeddings (graph_id, label, content, model, model_id, tlp_level)
values (-9020, 'CgAppDoc', 'clear', 'cgapp-model', 'cgapp-model', 0),
       (-9021, 'CgAppDoc', 'green', 'cgapp-model', 'cgapp-model', 1),
       (-9024, 'CgAppDoc', 'red',   'cgapp-model', 'cgapp-model', 4);

do $$
declare
    visible int;
begin
    set local role cg_app;
    perform set_config('app.max_tlp', '1', true);

    select count(*) into visible from embeddings where graph_id between -9024 and -9020;
    if visible <> 2 then
        raise exception
            'cg_app at max_tlp=1 saw % rows, expected 2 (0 would mean a missing grant, 3 means RLS is not binding)',
            visible;
    end if;

    -- Named separately, because a wrong count above could in principle come
    -- from the wrong two rows.
    select count(*) into visible from embeddings where graph_id = -9024;
    if visible <> 0 then
        raise exception 'cg_app at max_tlp=1 saw the TLP:4 row';
    end if;

    reset role;
end $$;

-- ============================================================
-- 3. Carve-outs from the broad table grant
-- ============================================================

do $$
begin
    -- Append-only audit log (024). INSERT yes, rewriting history no.
    if to_regclass('audit_log') is not null then
        if not has_table_privilege('cg_app', 'audit_log', 'INSERT') then
            raise exception 'cg_app cannot INSERT into audit_log';
        end if;
        if has_table_privilege('cg_app', 'audit_log', 'UPDATE') then
            raise exception 'cg_app can UPDATE audit_log; the log is append-only';
        end if;
        if has_table_privilege('cg_app', 'audit_log', 'DELETE') then
            raise exception 'cg_app can DELETE from audit_log; the log is append-only';
        end if;
    end if;

    -- AGE's graph and label registries. Writing them is DDL by another name.
    if to_regclass('ag_catalog.ag_label') is not null then
        if has_table_privilege('cg_app', 'ag_catalog.ag_label', 'INSERT') then
            raise exception 'cg_app can INSERT into ag_catalog.ag_label';
        end if;
        if not has_table_privilege('cg_app', 'ag_catalog.ag_label', 'SELECT') then
            raise exception 'cg_app cannot SELECT ag_catalog.ag_label; AGE needs to read it';
        end if;
    end if;
end $$;

-- ============================================================
-- 4. No CREATE anywhere
-- ============================================================

-- CREATE on the graph schema would let AGE auto-create a label's backing table
-- on first write, and that table would be owned by cg_app with no policy
-- attached: precisely the hole migration 028 had to close by hand. It does not
-- arise, because ingest/graph_writer.py drops any label without a
-- MERGE_TEMPLATES entry before it reaches Cypher. This asserts the grant side
-- of that argument.
do $$
declare
    sch text;
begin
    foreach sch in array array['public', 'ag_catalog', 'core_graph'] loop
        if exists (select 1 from pg_namespace where nspname = sch) then
            if has_schema_privilege('cg_app', sch, 'CREATE') then
                raise exception 'cg_app holds CREATE on schema %', sch;
            end if;
            if not has_schema_privilege('cg_app', sch, 'USAGE') then
                raise exception 'cg_app lacks USAGE on schema %', sch;
            end if;
        end if;
    end loop;
end $$;

-- ============================================================
-- Teardown
-- ============================================================

reset role;

delete from embeddings where graph_id between -9024 and -9020;
delete from embedding_models where model_id = 'cgapp-model';

-- cg_app is not dropped. It is a schema object created by a migration, not a
-- fixture created by this suite.

\echo 'tests/rls/test_application_role.sql: OK'
