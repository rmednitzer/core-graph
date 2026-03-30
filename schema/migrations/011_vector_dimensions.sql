-- 011_vector_dimensions.sql
-- Adjust embeddings table vector dimension to match configured model.
-- Default: 768 dimensions (nomic-embed-text). Original: 1536 (OpenAI).
-- Idempotent: only alters if current dimension differs.

-- Check current dimension and alter if needed.
-- Note: this migration drops and recreates the embedding column and HNSW
-- index. Existing embeddings generated with a different dimension will be
-- lost. Run re-embedding after this migration if data exists.

do $$
declare
    current_dim int;
    target_dim int := 768;  -- Match CG_EMBEDDING_DIMENSIONS default
begin
    -- Get current vector dimension from the column type
    select atttypmod
    into current_dim
    from pg_attribute
    where attrelid = 'embeddings'::regclass
      and attname = 'embedding';

    -- atttypmod for vector(N) stores N directly
    if current_dim is not null and current_dim != target_dim then
        -- Drop the HNSW index
        drop index if exists idx_embeddings_hnsw;

        -- Alter the column dimension
        alter table embeddings
            alter column embedding type vector(768);

        -- Recreate HNSW index with matching dimension
        create index idx_embeddings_hnsw
            on embeddings using hnsw (embedding vector_cosine_ops)
            with (m = 16, ef_construction = 200);

        raise notice 'Embeddings column altered from vector(%) to vector(%)',
            current_dim, target_dim;
    end if;
end $$;
