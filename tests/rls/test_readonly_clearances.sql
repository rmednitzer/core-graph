-- tests/rls/test_readonly_clearances.sql
-- Read-only clearances (migration 041).
--
-- Five of the seven clearances are described by Cerbos and by
-- docs/architecture/authorization-model.md as review, oversight, monitoring,
-- audit or analysis roles, and 041 makes the database agree. The value of that
-- is precisely that it does not depend on a policy predicate being right: 028's
-- write policies are predicates, and a predicate that is wrong is a hole, while
-- a missing GRANT is not.
--
-- Two halves are tested, because the second is the one that rots quietly. The
-- table grants are the obvious half. The *default* privileges are the half that
-- silently undoes them: 040 set defaults granting write on tables created
-- later, so without 041 revoking those too, the next migration to add a table
-- would re-widen every read-only clearance with nothing to notice it.
--
-- Does not pin search_path, for the reason recorded in test_vector_tlp.sql.

\set ON_ERROR_STOP on

-- ============================================================
-- 1. The split, as the catalogue sees it
-- ============================================================

do $$
declare
    r        text;
    n_write  bigint;
begin
    -- cg_ai_agent is deliberately absent: migration 042 gives it write on the
    -- memory layer and only there, following policies/resource/memory.yaml.
    -- Section 4 asserts that scope, which is a stronger claim than the blanket
    -- one made here and would be lost if it were folded in.
    foreach r in array array['cg_compliance_officer', 'cg_it_operations', 'cg_dpo',
                             'cg_external_auditor'] loop
        select count(*) into n_write
          from information_schema.table_privileges
         where grantee = r
           and table_schema in ('public', 'ag_catalog', 'core_graph')
           and privilege_type in ('UPDATE', 'DELETE');
        if n_write <> 0 then
            raise exception '% holds UPDATE or DELETE on % table(s); it is a read-only clearance',
                r, n_write;
        end if;

        -- INSERT survives on exactly one table: the audit log, because every
        -- audited tool writes an entry and revoking it would fail every call by
        -- a read-only caller rather than only its writes.
        select count(*) into n_write
          from information_schema.table_privileges
         where grantee = r
           and table_schema in ('public', 'ag_catalog', 'core_graph')
           and privilege_type = 'INSERT';
        if n_write <> 1 then
            raise exception
                '% holds INSERT on % tables, expected exactly 1 (audit_log)', r, n_write;
        end if;

        if not has_table_privilege(r, 'audit_log', 'INSERT') then
            raise exception '% cannot write audit entries, so every call by it would fail', r;
        end if;
    end loop;
end $$;

-- The two operational clearances keep their write surface, or this migration
-- narrowed the wrong thing. Cerbos allows ciso `*` on three resources plus the
-- sole `assert` on identity_attribution, and soc_analyst `incident:update`.
do $$
declare
    r       text;
    n_write bigint;
begin
    foreach r in array array['cg_ciso', 'cg_soc_analyst'] loop
        select count(*) into n_write
          from information_schema.table_privileges
         where grantee = r
           and table_schema in ('public', 'ag_catalog', 'core_graph')
           and privilege_type = 'UPDATE';
        if n_write = 0 then
            raise exception '% lost its write surface; Cerbos grants it mutating actions', r;
        end if;
    end loop;
end $$;

-- ============================================================
-- 2. The split, as a caller finds out
-- ============================================================

-- The catalogue assertion above would pass on a database where the grant is
-- absent but something else re-adds it at runtime. This is the same claim made
-- the way a request makes it.

-- The model is registered first so the insert below can only fail one way.
-- Without it the row would also violate the embeddings.model_id foreign key,
-- and the test would be resting on PostgreSQL checking privileges before
-- constraints rather than on the grant being absent.
delete from embeddings where graph_id = -9500;
insert into embedding_models (model_id, dim) values ('t-readonly', 768)
on conflict (model_id) do nothing;

do $$
declare
    denied boolean := false;
begin
    set local role cg_external_auditor;
    begin
        insert into embeddings (graph_id, label, content, model, model_id, tlp_level)
        values (-9500, 'RoDoc', 'x', 't-readonly', 't-readonly', 0);
    exception
        when insufficient_privilege then denied := true;
    end;
    reset role;

    if not denied then
        raise exception
            'cg_external_auditor wrote to embeddings; a read-only clearance must be '
            'stopped by the grant, not by a policy predicate';
    end if;
end $$;

-- The audit log's own writability is asserted with has_table_privilege in
-- section 1 rather than by inserting a row. 008 puts BEFORE UPDATE/DELETE
-- triggers on audit_log and 024 blocks TRUNCATE, so a test row could not be
-- removed afterwards -- and writing evidence-chain entries that exist only to
-- be tidied away is exactly what "append-only" is supposed to prevent.

-- ============================================================
-- 3. A later migration must not re-widen them
-- ============================================================

-- The half that rots quietly. `pg_default_acl` holds what a newly created table
-- will grant; if a read-only clearance appears there with write, the next
-- migration that adds a table hands it back everything 041 removed.
do $$
declare
    r    text;
    acl  aclitem[];
    bad  text;
begin
    foreach r in array array['cg_compliance_officer', 'cg_it_operations', 'cg_dpo',
                             'cg_external_auditor', 'cg_ai_agent'] loop
        for acl in
            select d.defaclacl from pg_default_acl d
             join pg_namespace n on n.oid = d.defaclnamespace
            where d.defaclobjtype = 'r'
              and n.nspname in ('public', 'ag_catalog', 'core_graph')
        loop
            select a::text into bad
              from unnest(acl) as a
             where a::text like r || '=%'
               and (a::text ~ ('^' || r || '=[^/]*a')     -- INSERT
                 or a::text ~ ('^' || r || '=[^/]*w')     -- UPDATE
                 or a::text ~ ('^' || r || '=[^/]*d'));   -- DELETE
            if bad is not null then
                raise exception
                    'default privileges still grant % write (%); the next migration to '
                    'add a table would re-widen it', r, bad;
            end if;
        end loop;
    end loop;
end $$;

-- ============================================================
-- 4. cg_ai_agent writes memory, and only memory
-- ============================================================

-- Migration 042 is the one exception to 041, and an exception is only as good
-- as its boundary. Cerbos grants ai_agent create/update on `memory` and on
-- nothing else, so the grant has to stop there too -- otherwise the engine and
-- the authorization model drift apart again, which is the condition ADR-0016
-- exists to end.
do $$
declare
    n_memory     bigint;
    n_non_memory bigint;
    n_delete     bigint;
    memory_rel   text[] := array['Session', 'Episode', 'ExtractedFact', 'ConceptEntity',
                                 'belongs_to', 'extracted_from', 'mentions', 'supersedes',
                                 'memory_session_counters', 'memory_extracted_fact_index',
                                 'memory_episode_salience'];
begin
    select count(*) into n_memory
      from information_schema.table_privileges
     where grantee = 'cg_ai_agent'
       and privilege_type in ('INSERT', 'UPDATE')
       and table_name = any (memory_rel);
    if n_memory = 0 then
        raise exception
            'cg_ai_agent has no write on the memory layer; Layer 5 is unwritable by '
            'the role it exists for (migration 042)';
    end if;

    -- The boundary. audit_log is the one non-memory table it may insert into,
    -- for the reason section 1 records: every audited tool writes an entry.
    select count(*) into n_non_memory
      from information_schema.table_privileges
     where grantee = 'cg_ai_agent'
       and table_schema in ('public', 'ag_catalog', 'core_graph')
       and privilege_type in ('INSERT', 'UPDATE')
       and not (table_name = any (memory_rel))
       and table_name <> 'audit_log';
    if n_non_memory <> 0 then
        raise exception
            'cg_ai_agent can write % table(s) outside the memory layer; Cerbos grants '
            'it mutating actions on `memory` and nothing else', n_non_memory;
    end if;

    -- Bitemporal: facts are invalidated, never deleted. 020 enforces it with a
    -- trigger; this asserts the grant agrees, so the trigger is a backstop
    -- rather than the only thing standing there.
    select count(*) into n_delete
      from information_schema.table_privileges
     where grantee = 'cg_ai_agent'
       and table_schema in ('public', 'ag_catalog', 'core_graph')
       and privilege_type = 'DELETE';
    if n_delete <> 0 then
        raise exception
            'cg_ai_agent holds DELETE on % table(s); memory is bitemporal and Cerbos '
            'denies it delete', n_delete;
    end if;
end $$;

-- ============================================================
-- Teardown
-- ============================================================

reset role;

delete from embeddings where graph_id = -9500;
delete from embedding_models where model_id = 't-readonly';

\echo 'tests/rls/test_readonly_clearances.sql: OK'
