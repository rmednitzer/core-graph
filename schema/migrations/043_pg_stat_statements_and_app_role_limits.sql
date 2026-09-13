\echo 'applying 043_pg_stat_statements_and_app_role_limits.sql'
-- 043_pg_stat_statements_and_app_role_limits.sql
-- Query-performance evidence, and session limits scoped to the serving role.
--
-- Derived from the reference production deployment (PostgreSQL 18, AGE,
-- pgvector, pg_cron, pgaudit on one host), where pg_stat_statements is the
-- evidence source for slow-query review and statement ceilings are not
-- applied cluster-wide. Two changes:
--
-- 1. pg_stat_statements. Created here so the extension exists on every
--    deployment that runs the migration chain. The library must ALSO be in
--    shared_preload_libraries (deploy/docker/postgresql-hardened.conf,
--    docker-compose.yml, the Helm statefulset, and the CI action all preload
--    it); without that the view exists but raises at query time.
--
-- 2. Session limits on cg_app (migration 038), the request-serving role.
--    postgresql-hardened.conf used to set statement_timeout = '30s' globally,
--    which also cut off the owner identity that runs migrations and builds
--    HNSW indexes, and pg_cron jobs. The ceiling belongs on the role that
--    serves requests. api.db still sets a role-derived statement_timeout on
--    every pooled connection; this role default covers connections that do
--    not go through the pool (psql as cg_app, ad-hoc tooling).
--
-- Idempotent: CREATE EXTENSION IF NOT EXISTS, and ALTER ROLE ... SET is
-- itself idempotent. Guarded on the role existing so the chain still applies
-- on a database where 038 has not created cg_app yet.

create extension if not exists pg_stat_statements;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'cg_app') then
        execute 'alter role cg_app set statement_timeout = ''30s''';
        execute 'alter role cg_app set idle_in_transaction_session_timeout = ''60s''';
        raise notice 'cg_app session limits set (statement_timeout 30s, idle_in_transaction 60s)';
    else
        raise notice 'cg_app does not exist; session limits skipped (migration 038 not applied)';
    end if;
end $$;
