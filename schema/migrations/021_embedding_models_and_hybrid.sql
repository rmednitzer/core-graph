\echo 'applying 021_embedding_models_and_hybrid.sql'
-- 021_embedding_models_and_hybrid.sql
-- Phase 1 — vector layer modernisation.
--
-- Adds:
--   1. embedding_models registry (model_id, dim, lifecycle timestamps).
--   2. embeddings.model_id FK referencing the registry.
--   3. embeddings.embedding_half (halfvec) populated by trigger from `embedding`.
--   4. embeddings.content_tsv (tsvector) populated by trigger from `content`.
--   5. Per-model partial HNSW indexes for both full and half precision
--      (one initial pair seeded for the default model). Operators add new
--      models via the helper function cg_register_embedding_model().
--   6. GIN index on content_tsv for BM25 ranking via ts_rank_cd.
--
-- Multi-dim caveat: this migration assumes all registered embedding models
-- share the dim of the embeddings.embedding column (current target: 768).
-- Registering a model at a different dim raises an exception. Multi-dim
-- support requires a partitioned table, which is out of scope for Phase 1.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. embedding_models registry
-- ---------------------------------------------------------------------------

create table if not exists embedding_models (
    model_id      text primary key,
    dim           int not null,
    created_at    timestamptz not null default now(),
    deprecated_at timestamptz
);

create index if not exists idx_embedding_models_active
    on embedding_models (model_id)
    where deprecated_at is null;

-- Seed the default model. The dim must match the embeddings column dim.
do $$
declare
    target_dim int;
begin
    select atttypmod into target_dim
      from pg_attribute
     where attrelid = 'embeddings'::regclass
       and attname  = 'embedding';
    if target_dim is null or target_dim < 0 then
        target_dim := 768;
    end if;

    insert into embedding_models (model_id, dim)
         values ('nomic-embed-text', target_dim)
    on conflict (model_id) do nothing;
end $$;

-- ---------------------------------------------------------------------------
-- 2. embeddings.model_id FK
-- ---------------------------------------------------------------------------

alter table embeddings
    add column if not exists model_id text;

-- Backfill from the legacy `model` text column where present.
update embeddings
   set model_id = model
 where model_id is null
   and model is not null;

-- For any rows still without a model_id, assign the default registered model.
update embeddings
   set model_id = (
       select model_id from embedding_models
        where deprecated_at is null
        order by created_at asc
        limit 1
   )
 where model_id is null;

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'fk_embeddings_model'
           and conrelid = 'embeddings'::regclass
    ) then
        alter table embeddings
            add constraint fk_embeddings_model
            foreign key (model_id) references embedding_models(model_id);
    end if;
end $$;

create index if not exists idx_embeddings_model_id
    on embeddings (model_id);

-- ---------------------------------------------------------------------------
-- 3. halfvec column + auto-population trigger
-- ---------------------------------------------------------------------------

do $$
declare
    target_dim int;
begin
    select atttypmod into target_dim
      from pg_attribute
     where attrelid = 'embeddings'::regclass
       and attname  = 'embedding';
    if target_dim is null or target_dim < 0 then
        target_dim := 768;
    end if;

    if not exists (
        select 1 from pg_attribute
         where attrelid = 'embeddings'::regclass
           and attname  = 'embedding_half'
           and not attisdropped
    ) then
        execute format(
            'alter table embeddings add column embedding_half halfvec(%s)',
            target_dim
        );
    end if;
end $$;

create or replace function embeddings_set_halfvec()
returns trigger as $$
begin
    if new.embedding is not null then
        new.embedding_half := new.embedding::halfvec;
    end if;
    return new;
end;
$$ language plpgsql;

drop trigger if exists trg_embeddings_set_halfvec on embeddings;
create trigger trg_embeddings_set_halfvec
    before insert or update of embedding on embeddings
    for each row execute function embeddings_set_halfvec();

-- Backfill halfvec for existing rows.
update embeddings
   set embedding_half = embedding::halfvec
 where embedding is not null
   and embedding_half is null;

-- ---------------------------------------------------------------------------
-- 4. tsvector column + auto-population trigger (BM25 retrieval)
-- ---------------------------------------------------------------------------

alter table embeddings
    add column if not exists content_tsv tsvector;

create or replace function embeddings_set_content_tsv()
returns trigger as $$
begin
    new.content_tsv := to_tsvector('simple', coalesce(new.content, ''));
    return new;
end;
$$ language plpgsql;

drop trigger if exists trg_embeddings_set_content_tsv on embeddings;
create trigger trg_embeddings_set_content_tsv
    before insert or update of content on embeddings
    for each row execute function embeddings_set_content_tsv();

update embeddings
   set content_tsv = to_tsvector('simple', coalesce(content, ''))
 where content_tsv is null;

create index if not exists idx_embeddings_content_tsv
    on embeddings using gin (content_tsv);

-- ---------------------------------------------------------------------------
-- 5. Per-model HNSW index helpers
-- ---------------------------------------------------------------------------

-- Validate model_id-as-identifier-suffix to avoid SQL injection in DDL.
create or replace function cg_validate_model_suffix(model_id text)
returns text as $$
declare
    safe text;
begin
    safe := regexp_replace(lower(model_id), '[^a-z0-9_]', '_', 'g');
    if length(safe) = 0 or length(safe) > 40 then
        raise exception 'invalid model_id for index suffix: %', model_id;
    end if;
    return safe;
end;
$$ language plpgsql immutable;

create or replace function cg_create_model_indexes(model_id_in text)
returns void as $$
declare
    suffix    text;
    rec_dim   int;
    target_dim int;
    has_halfvec boolean;
begin
    select dim into rec_dim from embedding_models where model_id = model_id_in;
    if rec_dim is null then
        raise exception 'embedding_models has no row for %', model_id_in;
    end if;

    select atttypmod into target_dim
      from pg_attribute
     where attrelid = 'embeddings'::regclass
       and attname  = 'embedding';

    if target_dim is not null and target_dim > 0 and rec_dim <> target_dim then
        raise exception
            'model % has dim % but embeddings column dim is % (multi-dim not supported)',
            model_id_in, rec_dim, target_dim;
    end if;

    suffix := cg_validate_model_suffix(model_id_in);

    execute format(
        'create index if not exists idx_embeddings_hnsw_%s '
        'on embeddings using hnsw (embedding vector_cosine_ops) '
        'with (m = 16, ef_construction = 200) '
        'where model_id = %L',
        suffix, model_id_in
    );

    -- halfvec index requires both pgvector >= 0.7.0 and the embedding_half
    -- column populated by section (3) above.
    select exists (select 1 from pg_type where typname = 'halfvec') into has_halfvec;
    if has_halfvec and exists (
        select 1 from pg_attribute
         where attrelid = 'embeddings'::regclass
           and attname  = 'embedding_half'
           and not attisdropped
    ) then
        execute format(
            'create index if not exists idx_embeddings_hnsw_half_%s '
            'on embeddings using hnsw (embedding_half halfvec_cosine_ops) '
            'with (m = 16, ef_construction = 200) '
            'where model_id = %L',
            suffix, model_id_in
        );
    end if;
end;
$$ language plpgsql;

create or replace function cg_register_embedding_model(model_id_in text, dim_in int)
returns void as $$
begin
    insert into embedding_models (model_id, dim)
         values (model_id_in, dim_in)
    on conflict (model_id) do update set deprecated_at = null;
    perform cg_create_model_indexes(model_id_in);
end;
$$ language plpgsql;

-- Ensure the seeded model has its index pair.
select cg_create_model_indexes(model_id)
  from embedding_models
 where deprecated_at is null;
