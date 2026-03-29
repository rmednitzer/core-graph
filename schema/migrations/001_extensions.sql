-- 001_extensions.sql
-- Install required PostgreSQL extensions for core-graph.
-- Idempotent: safe to run multiple times.

-- Apache AGE: openCypher graph queries
CREATE EXTENSION IF NOT EXISTS age;

-- pgvector: HNSW vector similarity search
CREATE EXTENSION IF NOT EXISTS vector;

-- pgAudit: audit logging for compliance
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- pg_cron: scheduled jobs (retention, Merkle root computation)
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Load AGE into the search path for all sessions
ALTER DATABASE current_database() SET search_path = ag_catalog, "$user", public;
