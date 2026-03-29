-- 003_vector_tables.sql
-- Relational tables for pgvector embeddings and user clearances.
-- Idempotent: safe to run multiple times.

create table if not exists embeddings (
    id          bigserial primary key,
    graph_id    bigint not null,
    label       text not null,
    content     text,
    embedding   vector(1536),
    model       text not null,
    created_at  timestamptz not null default now()
);

create index if not exists idx_embeddings_hnsw
    on embeddings using hnsw (embedding vector_cosine_ops)
    with (m = 16, ef_construction = 200);

create index if not exists idx_embeddings_graph_id
    on embeddings (graph_id);

create table if not exists user_clearances (
    user_id     text primary key,
    max_tlp     int not null default 1,
    compartments text[] not null default '{}'
);
