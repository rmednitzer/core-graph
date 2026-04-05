-- 019_embedding_metadata.sql
-- Add model version tracking to embeddings table.
-- Idempotent.

alter table embeddings
    add column if not exists model_version text;

-- Add embedded_at as nullable first to avoid a full table rewrite from a
-- volatile default (now()), then set the default for new rows only.
alter table embeddings
    add column if not exists embedded_at timestamptz;

alter table embeddings
    alter column embedded_at set default now();
