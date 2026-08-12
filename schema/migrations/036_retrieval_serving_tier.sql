\echo 'applying 036_retrieval_serving_tier.sql'
-- 036_retrieval_serving_tier.sql
-- Native-halfvec serving tier, keyed (graph_id, model_id).
--
-- Resolves ADR-0010 open questions 1 and 2. See ADR-0011.
--
-- Shape is taken from axiom_kg's `retrieval_embeddings`, which is the same
-- design running in production:
--
--     document_id bigint, model_id text, embedding halfvec(512),
--     created_at timestamptz, primary key (document_id, model_id)
--
-- plus one partial HNSW index per model. Faithfully mirrored, including what
-- it does *not* carry: no full-precision twin, and no tlp_level (axiom keeps
-- that on its legacy `embeddings`, not on the serving tier).
--
-- What this replaces. Migration 021 put both `embedding vector(N)` and a
-- trigger-derived `embedding_half halfvec(N)` on one table, and built an HNSW
-- index over each per model. That is two copies of every vector and two graphs
-- per model. Measured on axiom: 12.7 kB/row for the equivalent dual-column
-- table against 2.8 kB/row for the halfvec-only serving table.
--
-- Why the index needs no `where retrieval_active` predicate (ADR-0010 open
-- question 2): this table holds rows only for retrieval-active subjects, so
-- the index is small because the *table* is small. axiom demonstrates the
-- ratio directly, 176,235 documents against 51,100 vector rows per model.
-- Predicating an index over a table that also holds cold rows would have
-- shrunk the index while leaving the heap to grow.
--
-- `embeddings` is unchanged and remains the identity and full-precision
-- record for every subject, hot or cold, exactly as axiom keeps its own
-- legacy pair. Nothing is dropped here, so this is reversible by pointing the
-- query path back at `embeddings`.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Serving table
-- ---------------------------------------------------------------------------

-- The dimension tracks `embeddings.embedding`, read from the catalogue the way
-- migration 021 does, so this migration cannot drift from the column it is
-- derived from.
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

    -- Deliberately NOT schema-qualified. Migration 001 sets the database
    -- search_path to ag_catalog,"$user",public, so the unqualified CREATE
    -- below resolves to the first schema on that path, not to public. A
    -- `to_regclass('public.retrieval_embeddings')` guard asks a different
    -- question than the CREATE answers: it reports NULL on the second pass
    -- even though the table exists, and the migration then fails as
    -- "relation already exists". The guard has to resolve exactly the way
    -- the CREATE does. Same trap documented in tests/rls/test_tlp_enforcement.sql.
    if to_regclass('retrieval_embeddings') is null then
        execute format(
            'create table retrieval_embeddings (
                 graph_id   bigint      not null,
                 model_id   text        not null references retrieval_models(model_id),
                 embedding  halfvec(%s) not null,
                 created_at timestamptz not null default now(),
                 primary key (graph_id, model_id)
             )',
            target_dim
        );
    end if;
end $$;

create index if not exists idx_retrieval_embeddings_model
    on retrieval_embeddings (model_id);

-- ---------------------------------------------------------------------------
-- 2. Per-model HNSW
-- ---------------------------------------------------------------------------

-- One partial index per model, matching axiom's idx_retrieval_<model>_hnsw
-- pair. A single index over the whole table would mix vector spaces that are
-- not comparable, and pgvector cannot tell them apart.
create or replace function cg_create_serving_index(model_id_in text)
returns void as $$
declare
    suffix text;
    rec    record;
begin
    select model_id, kind into rec
      from retrieval_models
     where model_id = model_id_in;

    if rec.model_id is null then
        raise exception 'retrieval_models has no row for %', model_id_in;
    end if;

    -- A reranker has no vector space, so it gets no index. Returning quietly
    -- rather than raising keeps this callable over the whole registry.
    if rec.kind <> 'embedding' then
        return;
    end if;

    suffix := cg_validate_model_suffix(model_id_in);

    execute format(
        'create index if not exists idx_retrieval_hnsw_%s '
        'on retrieval_embeddings using hnsw (embedding halfvec_cosine_ops) '
        'with (m = 16, ef_construction = 200) '
        'where model_id = %L',
        suffix, model_id_in
    );
end;
$$ language plpgsql;

-- ---------------------------------------------------------------------------
-- 3. Backfill from the retrieval-active half of `embeddings`
-- ---------------------------------------------------------------------------

-- Only retrieval-active subjects get a serving row; that is the whole point of
-- the split. `embedding_half` is already populated by 021's trigger, so no
-- re-embedding is needed and the backfill is a copy.
insert into retrieval_embeddings (graph_id, model_id, embedding)
select e.graph_id, e.model_id, e.embedding_half
  from embeddings e
  join retrieval_models rm
    on rm.model_id = e.model_id
   and rm.kind = 'embedding'
 where e.retrieval_active
   and e.embedding_half is not null
   and e.model_id is not null
on conflict (graph_id, model_id) do nothing;

-- Build the index pair after the backfill, not before: HNSW build over a
-- populated table is far cheaper than incremental insertion into an empty one.
select cg_create_serving_index(model_id)
  from retrieval_models
 where active
   and kind = 'embedding';

-- ---------------------------------------------------------------------------
-- 4. Parity now measures the serving tier
-- ---------------------------------------------------------------------------

-- 035 measured parity over `embeddings`, which was the only vector store at
-- the time. The serving tier is what retrieval actually reads, so that is what
-- a gap has to be measured against.
create or replace view cg_retrieval_parity as
with active_models as (
    select model_id
      from retrieval_models
     where active
       and kind = 'embedding'
),
subject_total as (
    select count(distinct graph_id) as n
      from embeddings
     where retrieval_active
)
select am.model_id,
       (select n from subject_total)                              as active_subjects,
       count(re.graph_id)                                         as vectors,
       (select n from subject_total) - count(re.graph_id)          as gap
  from active_models am
  left join retrieval_embeddings re
         on re.model_id = am.model_id
 group by am.model_id;

comment on view cg_retrieval_parity is
    'Per active embedding model: retrieval-active subjects, serving-tier '
    'vectors present, and the gap between them. A non-zero gap means one '
    'vector space covers less of the corpus than another, which biases hybrid '
    'fusion silently. Measured against retrieval_embeddings since 036.';
