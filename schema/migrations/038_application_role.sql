\echo 'applying 038_application_role.sql'
-- 038_application_role.sql
-- A non-superuser application role, so RLS is actually evaluated.
--
-- The gap this exists for, recorded in ADR-0011 and the 037 header: no RLS
-- policy in this repository is evaluated for the application's connection.
-- The cg_* roles from 004, 005 and 010 are NOLOGIN, so they are grant targets
-- rather than connection identities. Nothing outside tests issues SET ROLE;
-- get_connection() sets app.max_tlp as a GUC and leaves the session role
-- alone. And the application connects as cg_admin, which is POSTGRES_USER in
-- the official postgres image and therefore a superuser. Superusers bypass
-- row-level security unconditionally, ENABLE and FORCE alike, so every policy
-- on every table is inert for the application.
--
-- The policies key off the app.max_tlp GUC rather than off the role, so the
-- fix does not need per-request SET ROLE. It needs the application to stop
-- being a superuser. This migration creates the role that makes that possible.
--
-- THIS MIGRATION DOES NOT SWITCH ANYTHING OVER. It is additive: nothing uses
-- cg_app until a deployment points CG_PG_DSN at it. That is deliberate, so the
-- role and its grant surface can be reviewed and tested before anything
-- depends on them. Switching over is a change to deploy/docker/docker-compose.yml
-- and the CI env, and it is where grant-completeness gets proven, because the
-- integration suite exercises the real read and write paths.
--
-- Why no CREATE on the graph schema. AGE creates a label's backing table on
-- first `CREATE (n:Label)`, which is DDL a non-owner cannot perform. That
-- would have forced a CREATE grant, and any table AGE then created would be
-- owned by cg_app with no RLS policy attached, which is precisely the hole
-- migration 028 had to close by hand for the 009/023 labels. It does not
-- arise: ingest/graph_writer.py resolves every label through MERGE_TEMPLATES
-- and returns None when there is no template, so an unknown label from a
-- message payload is logged and dropped rather than reaching Cypher. The
-- templates cover only labels the migrations already create.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. The role
-- ---------------------------------------------------------------------------

-- No password is set here. A migration is the wrong place for a credential,
-- and a role created with a default one is worse than a role that cannot yet
-- connect. Deployment sets it (dev via docker-compose, CI via its env), which
-- is also what activates the role.
--
-- NOBYPASSRLS is stated explicitly rather than left to the default. It is the
-- single attribute this entire migration exists to guarantee, and an
-- explicit declaration is what a reviewer checks.
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_app') then
        create role cg_app login nosuperuser nocreatedb nocreaterole noinherit nobypassrls;
    else
        alter role cg_app nosuperuser nocreatedb nocreaterole nobypassrls;
    end if;
end $$;

-- PUBLIC holds CONNECT on a database by default, so this is usually a no-op.
-- Stated anyway: a deployment that has revoked it from PUBLIC would otherwise
-- leave cg_app unable to connect, and the failure would look like a bad
-- password rather than a missing grant.
do $$
begin
    execute format('grant connect on database %I to cg_app', current_database());
end $$;

-- ---------------------------------------------------------------------------
-- 2. Schema access
-- ---------------------------------------------------------------------------

-- USAGE only, never CREATE. Without USAGE the role gets "relation does not
-- exist" rather than a permission error, which reads as an empty result and
-- would make a test pass vacuously; the same hazard tests/rls/test_vector_tlp.sql
-- documents.
do $$
declare
    sch text;
begin
    foreach sch in array array['public', 'ag_catalog', 'core_graph'] loop
        if exists (select 1 from pg_namespace where nspname = sch) then
            execute format('grant usage on schema %I to cg_app', sch);
        end if;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Data access
-- ---------------------------------------------------------------------------

-- Table-level grants are deliberately broad and row-level access is what
-- constrains them. That is the model 004 already established: it grants SELECT
-- on every core_graph table to all seven clearance roles and lets the TLP
-- policy decide which rows each one sees. Narrowing table grants instead would
-- duplicate the policy in a second place that can drift from it.
do $$
declare
    sch text;
begin
    foreach sch in array array['public', 'ag_catalog', 'core_graph'] loop
        if exists (select 1 from pg_namespace where nspname = sch) then
            execute format(
                'grant select, insert, update, delete on all tables in schema %I to cg_app', sch
            );
            -- bigserial columns need the sequence, or every insert fails.
            execute format('grant usage, select on all sequences in schema %I to cg_app', sch);
            -- ag_catalog.cypher() and the cg_* helper functions.
            execute format('grant execute on all functions in schema %I to cg_app', sch);

            -- Objects created by later migrations, so this does not silently
            -- go stale the next time a table is added. Default privileges are
            -- scoped to the role that declares them, so this covers exactly
            -- what the migration runner creates, which is every schema object
            -- in this repository.
            execute format(
                'alter default privileges in schema %I '
                'grant select, insert, update, delete on tables to cg_app', sch
            );
            execute format(
                'alter default privileges in schema %I grant usage, select on sequences to cg_app',
                sch
            );
            execute format(
                'alter default privileges in schema %I grant execute on functions to cg_app', sch
            );
        end if;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 4. Carve-outs from the broad grant
-- ---------------------------------------------------------------------------

-- Audit rows are append-only (024). cg_audit_writer already holds the INSERT
-- grant; the broad grant above would hand cg_app UPDATE and DELETE on the
-- audit log, which no application path should have and which contradicts the
-- append-only property the evidence chain rests on.
do $$
begin
    if to_regclass('audit_log') is not null then
        execute 'revoke update, delete on audit_log from cg_app';
    end if;
end $$;

-- AGE's own catalogue. `ag_graph` and `ag_label` are the graph and label
-- registries; writing to them is DDL by another name, and the broad grant on
-- schema ag_catalog would have included them. The application never needs it,
-- for the same reason it needs no CREATE: MERGE_TEMPLATES fixes the label set,
-- so no new label is ever registered at runtime.
--
-- Note the schema qualification here, unlike everywhere else in this file. It
-- is load-bearing: `embeddings`, `retrieval_embeddings`, `retrieval_models` and
-- `embedding_models` also live in ag_catalog, because migration 001 puts it
-- first on the database search_path and the unqualified CREATE TABLE in 003,
-- 021, 034 and 036 followed it there. A blanket revoke on the schema would
-- take the vector tier with it.
do $$
declare
    rel text;
begin
    foreach rel in array array['ag_catalog.ag_graph', 'ag_catalog.ag_label'] loop
        if to_regclass(rel) is not null then
            execute format('revoke insert, update, delete on %s from cg_app', rel);
        end if;
    end loop;
end $$;
