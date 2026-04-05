-- 019_embedding_metadata.sql
-- Add model version tracking to embeddings table.
-- Idempotent.

alter table embeddings
    add column if not exists model_version text;

alter table embeddings
    add column if not exists embedded_at timestamptz default now();
