-- tests/rls/test_vector_tlp.sql
-- RLS enforcement on the vector tier (migration 037).
--
-- Until 037 the vector tables carried no policy at all, so retrieval returned
-- content at any TLP level to any caller. tests/eval/test_rls_retrieval_
-- correctness.py asserts the same property end to end, but it needs an
-- embedding provider and CI has none, so it has never run. This suite asserts
-- the engine-level half, which needs nothing but psql, and therefore actually
-- runs in schema-and-rls-test.
--
-- Creates its own roles and rows, asserts, then removes everything it made.

\set ON_ERROR_STOP on

-- Deliberately does NOT pin `search_path = public`.
--
-- test_tlp_enforcement.sql does pin it, because it creates its own stand-in
-- table and needs that table in public. This suite uses the *real* vector
-- tables, and they are not in public: migration 001 sets the database
-- search_path to ag_catalog,"$user",public, so the unqualified CREATE TABLE in
-- 003 and 036 landed them in ag_catalog. Pinning public here hides them and
-- the suite dies on "relation embeddings does not exist".
--
-- Inheriting the database default resolves them correctly. The schema is
-- resolved from the catalogue below rather than assumed, so this keeps working
-- if the placement ever changes.

-- ============================================================
-- Setup
-- ============================================================

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'vtlp_low') then
        create role vtlp_low nologin;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'vtlp_high') then
        create role vtlp_high nologin;
    end if;
end $$;

-- The non-superuser test roles need USAGE on whichever schema holds the tables,
-- or SELECT resolves to "relation does not exist" for them and every assertion
-- below passes vacuously. test_tlp_enforcement.sql records the same hazard.
do $$
declare
    sch text;
begin
    select n.nspname into sch
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
     where c.relname = 'embeddings'
       and c.relkind = 'r'
     limit 1;

    if sch is null then
        raise exception 'cannot locate the embeddings table in any schema';
    end if;

    execute format('grant usage on schema %I to vtlp_low, vtlp_high', sch);
end $$;

grant select on embeddings to vtlp_low, vtlp_high;
grant select on retrieval_embeddings to vtlp_low, vtlp_high;

insert into embedding_models (model_id, dim) values ('vtlp-model', 768)
on conflict (model_id) do nothing;

select cg_register_retrieval_model('vtlp-model', 'embedding', 'test', 'test', 'test', 768);

-- One row per TLP level, at negative graph_ids so they cannot collide with
-- real data.
insert into embeddings (graph_id, label, content, model, model_id, tlp_level)
values (-9010, 'VtlpDoc', 'clear',      'vtlp-model', 'vtlp-model', 0),
       (-9011, 'VtlpDoc', 'green',      'vtlp-model', 'vtlp-model', 1),
       (-9012, 'VtlpDoc', 'amber',      'vtlp-model', 'vtlp-model', 2),
       (-9013, 'VtlpDoc', 'amberstrict','vtlp-model', 'vtlp-model', 3),
       (-9014, 'VtlpDoc', 'red',        'vtlp-model', 'vtlp-model', 4);

-- ============================================================
-- Assertions
-- ============================================================

do $$
declare
    visible int;
begin
    -- A caller cleared to 1 must see exactly the rows at 0 and 1.
    set local role vtlp_low;
    perform set_config('app.max_tlp', '1', true);
    select count(*) into visible from embeddings where graph_id between -9014 and -9010;
    if visible <> 2 then
        raise exception 'embeddings: max_tlp=1 saw % rows, expected 2', visible;
    end if;

    -- And must not see the TLP:RED row specifically.
    select count(*) into visible from embeddings where graph_id = -9014;
    if visible <> 0 then
        raise exception 'embeddings: max_tlp=1 leaked the TLP:4 row';
    end if;

    reset role;

    -- A caller cleared to 4 sees all five.
    set local role vtlp_high;
    perform set_config('app.max_tlp', '4', true);
    select count(*) into visible from embeddings where graph_id between -9014 and -9010;
    if visible <> 5 then
        raise exception 'embeddings: max_tlp=4 saw % rows, expected 5', visible;
    end if;

    reset role;

    -- An unset app.max_tlp must coalesce to the most restrictive reading, not
    -- to "no filter". This is the failure mode that would reintroduce the gap.
    set local role vtlp_low;
    perform set_config('app.max_tlp', '', true);
    select count(*) into visible from embeddings where graph_id between -9014 and -9010;
    if visible <> 2 then
        raise exception
            'embeddings: unset app.max_tlp saw % rows, expected 2 (coalesce to 1)', visible;
    end if;

    reset role;
end $$;

-- The serving tier carries its own level so the ANN scan is filtered before
-- top-k is chosen, not after. Assert the policy is present and effective there
-- too, using the rows 037's resync propagated.
-- The dimension is read from the catalogue rather than hardcoded: migration
-- 011 allows it to change, and 036 derives the serving column from the same
-- place. Hardcoding it here would make this suite fail on any deployment that
-- moved off the default.
do $$
declare
    dim int;
begin
    select atttypmod into dim
      from pg_attribute
     where attrelid = 'retrieval_embeddings'::regclass
       and attname  = 'embedding';

    execute format(
        'insert into retrieval_embeddings (graph_id, model_id, embedding, tlp_level)
         select graph_id, model_id,
                array_fill(0.1::real, array[%s])::vector::halfvec, tlp_level
           from embeddings
          where graph_id between -9014 and -9010
         on conflict (graph_id, model_id) do nothing',
        dim
    );
end $$;

do $$
declare
    visible int;
begin
    set local role vtlp_low;
    perform set_config('app.max_tlp', '1', true);
    select count(*) into visible
      from retrieval_embeddings where graph_id between -9014 and -9010;
    if visible <> 2 then
        raise exception
            'retrieval_embeddings: max_tlp=1 saw % rows, expected 2', visible;
    end if;
    reset role;
end $$;

-- ============================================================
-- Teardown
-- ============================================================

reset role;

delete from retrieval_embeddings where graph_id between -9014 and -9010;
delete from embeddings where graph_id between -9014 and -9010;
delete from retrieval_models where model_id = 'vtlp-model';
delete from embedding_models where model_id = 'vtlp-model';

revoke select on embeddings from vtlp_low, vtlp_high;
revoke select on retrieval_embeddings from vtlp_low, vtlp_high;

-- The schema USAGE grant is a dependency too. Revoking only the table SELECTs
-- leaves it behind, and DROP ROLE then fails with "cannot be dropped because
-- some objects depend on it / privileges for schema ag_catalog". Resolved from
-- the catalogue, exactly as the grant was.
do $$
declare
    sch text;
begin
    select n.nspname into sch
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
     where c.relname = 'embeddings'
       and c.relkind = 'r'
     limit 1;

    if sch is not null then
        execute format('revoke usage on schema %I from vtlp_low, vtlp_high', sch);
    end if;
end $$;

drop role if exists vtlp_low;
drop role if exists vtlp_high;

\echo 'tests/rls/test_vector_tlp.sql: OK'
