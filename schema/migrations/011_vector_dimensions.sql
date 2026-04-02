-- 011_vector_dimensions.sql
-- Adjust embeddings table vector dimension to match configured model.
-- Default: 768 dimensions (nomic-embed-text). Original: 1536 (OpenAI).
--
-- SAFETY: If the table contains data with a different dimension, this
-- migration truncates the embeddings table rather than failing. Embeddings
-- are derived data that can be regenerated from source content.
-- Idempotent: safe to run multiple times.
--
-- For production dimension changes with zero-downtime requirements, a
-- side-by-side column migration is preferred: add new column, backfill
-- with re-embedded vectors, swap, drop old column.

do $$
declare
    current_dim int;
    target_dim int := 768;
    row_count bigint;
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
        raise notice 'Truncating % embedding(s) with dimension %; re-embedding required',
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
