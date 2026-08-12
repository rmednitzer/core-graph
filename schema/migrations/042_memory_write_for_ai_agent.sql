\echo 'applying 042_memory_write_for_ai_agent.sql'
-- 042_memory_write_for_ai_agent.sql
-- Give cg_ai_agent write on the AI memory layer, and only there.
--
-- ADR-0017. Migration 041 made five clearances read-only, derived from the
-- mutating actions Cerbos grants. Cerbos had no memory resource at all, so
-- `ai_agent` came out with no write anywhere and Layer 5 (023) became
-- unwritable by the role it exists for. ADR-0016 named the remedy and refused
-- to take it inline: a Cerbos policy stating the decision, reviewable, and then
-- a grant that follows it. `policies/resource/memory.yaml` is that policy and
-- this is that grant.
--
-- The order matters and is the whole point. The grant below is derived from the
-- policy, so the engine and the authorization model say the same thing. A grant
-- written first, with the policy backfilled to match, would have been the
-- silent exception ADR-0016 exists to prevent.
--
-- ---------------------------------------------------------------------------
-- Scope: the memory layer, not "write"
-- ---------------------------------------------------------------------------
--
-- Cerbos grants ai_agent create/update on `memory` and on nothing else, so this
-- grant covers exactly the objects 023 created and nothing outside them. The
-- five other read-only clearances from 041 are untouched.
--
--   AGE labels in core_graph:  Session, Episode, ExtractedFact, ConceptEntity,
--                              belongs_to, extracted_from, mentions, supersedes
--   Shadow tables:             memory_session_counters,
--                              memory_extracted_fact_index,
--                              memory_episode_salience
--
-- ---------------------------------------------------------------------------
-- INSERT and UPDATE, never DELETE
-- ---------------------------------------------------------------------------
--
-- Memory is bitemporal: a superseded fact keeps its row and gains a
-- `t_superseded` stamp. 020 puts a delete-block trigger on the temporal tables
-- and the project conventions state facts are "invalidated, never deleted", so
-- a DELETE grant would describe an operation the model does not have. Cerbos
-- says the same, denying `delete` to ai_agent.
--
-- ---------------------------------------------------------------------------
-- Two grants that are not obvious from reading the tool code
-- ---------------------------------------------------------------------------
--
-- Both come from SECURITY INVOKER functions in 023, which run with the calling
-- role's privileges rather than the owner's, and both would fail at runtime
-- rather than in CI -- the integration suite runs as the dev identity, which
-- falls through to cg_app and never assumes a clearance at all.
--
--   * memory_session_counters needs UPDATE as well as INSERT.
--     `memory_next_sequence()` is `insert ... on conflict do update`, and
--     memory_remember calls it for every episode.
--
--   * memory_extracted_fact_index needs UPDATE as well as INSERT.
--     `trg_memory_supersession` is an AFTER INSERT trigger that updates the
--     same table to stamp t_superseded on the row it supersedes. An INSERT-only
--     grant would let the insert start and the trigger fail it.
--
-- Idempotent.

do $$
declare
    tbl text;
    n   int := 0;
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_ai_agent') then
        raise notice 'cg_ai_agent does not exist; nothing to grant';
        return;
    end if;

    -- The AGE label tables. Named from the catalogue rather than hardcoded:
    -- AGE creates them when 023 calls create_vlabel/create_elabel, and a label
    -- whose table does not exist yet must not fail the migration.
    for tbl in
        select quote_ident(n2.nspname) || '.' || quote_ident(c.relname)
          from pg_class c
          join pg_namespace n2 on n2.oid = c.relnamespace
         where n2.nspname = 'core_graph'
           and c.relkind = 'r'
           and c.relname in ('Session', 'Episode', 'ExtractedFact', 'ConceptEntity',
                             'belongs_to', 'extracted_from', 'mentions', 'supersedes')
    loop
        execute format('grant insert, update on %s to cg_ai_agent', tbl);
        n := n + 1;
    end loop;

    -- The relational shadow tables. Unqualified, so they resolve the way 023's
    -- unqualified CREATE TABLE did (ag_catalog, per the search_path 001 sets);
    -- a qualified guess would silently match nothing. Same trap ADR-0011
    -- records for migration 036.
    foreach tbl in array array['memory_session_counters',
                               'memory_extracted_fact_index',
                               'memory_episode_salience'] loop
        if to_regclass(tbl) is not null then
            execute format('grant insert, update on %s to cg_ai_agent', tbl);
            n := n + 1;
        end if;
    end loop;

    raise notice 'granted cg_ai_agent insert+update on % memory object(s)', n;
end $$;

-- Sequences backing any of the shadow tables. The broad sequence grant from 040
-- already covers these, and 041 did not revoke it, so this is belt and braces
-- rather than a fix -- stated because an INSERT that cannot reach its sequence
-- fails in a way that reads like a missing table grant.
do $$
declare
    seq text;
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_ai_agent') then
        return;
    end if;

    for seq in
        select quote_ident(n.nspname) || '.' || quote_ident(c.relname)
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where c.relkind = 'S'
           and c.relname like 'memory\_%'
    loop
        execute format('grant usage, select on sequence %s to cg_ai_agent', seq);
    end loop;
end $$;
