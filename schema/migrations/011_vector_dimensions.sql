\echo 'applying 011_vector_dimensions.sql'
-- 011_vector_dimensions.sql
-- Adjust embeddings table vector dimension to match configured model.
-- Default: 768 dimensions (nomic-embed-text). Original: 1536 (OpenAI).
--
-- SAFETY: If the embeddings table contains data with a different dimension this
-- migration REFUSES to run by default. Re-running with truncate enabled requires
-- the operator to set the GUC `app.allow_embedding_truncate=true` (session or
-- transaction-local). See docs/operations/database-migration-runbook.md.
--
-- For zero-downtime production dimension changes, use the side-by-side column
-- migration pattern (add new column, backfill with re-embedded vectors, swap,
-- drop old column) — not this migration.
--
-- Idempotent: safe to re-run when current and target dimensions match.

do $$
declare
    current_dim int;
    target_dim int := 768;
    row_count bigint;
    allow_truncate text;
begin
    -- Get current vector dimension from pg_attribute
    select atttypmod into current_dim
    from pg_attribute
    where attrelid = 'embeddings'::regclass
      and attname = 'embedding';

    if current_dim is null or current_dim = target_dim then
        raise notice 'Embeddings column already at target dimension (%) or not found', target_dim;
        return;
    end if;

    -- Check if table has data
    select count(*) into row_count from embeddings;

    if row_count > 0 then
        -- Refuse to truncate unless the operator has explicitly opted in via GUC.
        allow_truncate := lower(coalesce(current_setting('app.allow_embedding_truncate', true), ''));
        if allow_truncate not in ('true', 't', 'on', '1', 'yes') then
            raise exception
                'Refusing to truncate % embedding(s) at dimension % to migrate to dimension %. '
                'Set app.allow_embedding_truncate=true (e.g. SET LOCAL ...) or perform a '
                'side-by-side column migration. See database-migration-runbook.md.',
                row_count, current_dim, target_dim;
        end if;

        raise notice 'Truncating % embedding(s) with dimension % (operator opted in via app.allow_embedding_truncate); re-embedding required',
            row_count, current_dim;
        truncate table embeddings;
    end if;

    -- Drop HNSW index (dimension-specific, must be recreated)
    drop index if exists idx_embeddings_hnsw;

    -- Alter column to target dimension
    execute format(
        'alter table embeddings alter column embedding type vector(%s)',
        target_dim
    );

    -- Recreate HNSW index
    create index idx_embeddings_hnsw
        on embeddings using hnsw (embedding vector_cosine_ops)
        with (m = 16, ef_construction = 200);

    raise notice 'Embeddings column altered from vector(%) to vector(%), index recreated',
        current_dim, target_dim;
end $$;
