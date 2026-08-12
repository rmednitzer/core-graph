\echo 'applying 034_retrieval_model_registry.sql'
-- 034_retrieval_model_registry.sql
-- Retrieval model registry with supply-chain provenance, plus pg_trgm.
--
-- Reconciles this repository against the live axiom_kg database (PostgreSQL
-- 18.4, 176,235 documents, 51,100 retrieval-active). See ADR-0010.
--
-- Two gaps this closes:
--
--   1. `embedding_models` records only (model_id, dim). It cannot express a
--      reranker, and it records nothing about *which weights* produced a
--      vector. api/mcp/tools/hybrid_search.py reranks via CG_RERANKER_URL,
--      an environment variable with no registry row, so a reranked result
--      set carries no provenance at all. axiom_kg's `retrieval_models`
--      carries kind/provider/repo/revision/active, and its two active
--      rerankers are registered rows like any embedding model.
--
--   2. pg_trgm is absent here and present on axiom. ingest/resolver/ does
--      entity resolution with no trigram index available to it.
--
-- Why a new table rather than columns on `embedding_models`:
--
--   `make migrate` replays every migration on every run, in order. Migration
--   021 ends with
--       select cg_create_model_indexes(model_id) from embedding_models
--        where deprecated_at is null;
--   and `cg_create_model_indexes` raises when a row's dim is null. A reranker
--   has no dim. Adding a nullable-dim reranker row to `embedding_models`
--   would therefore make the *second* replay of 021 fail, because 021 also
--   re-creates `cg_create_model_indexes` and would overwrite any hardened
--   version installed here. Keeping the registry in its own table removes
--   the ordering hazard entirely.
--
--   This is also what axiom does: `embedding_models` + `embeddings` remain
--   the legacy identity pair, and the serving tier lives in `retrieval_*`.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. pg_trgm, for the entity resolver
-- ---------------------------------------------------------------------------

create extension if not exists pg_trgm;

-- ---------------------------------------------------------------------------
-- 2. retrieval_models registry
-- ---------------------------------------------------------------------------

create table if not exists retrieval_models (
    model_id   text primary key,
    kind       text        not null,
    provider   text        not null,
    repo       text        not null,
    revision   text        not null,
    dim        int,
    active     boolean     not null default true,
    created_at timestamptz not null default now()
);

-- `revision` is the load-bearing column: it pins the exact upstream commit of
-- the model weights, so a stored vector or a recorded ranking is traceable to
-- an immutable artifact rather than to a moving tag.

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'retrieval_models_kind_check'
           and conrelid = 'retrieval_models'::regclass
    ) then
        alter table retrieval_models
            add constraint retrieval_models_kind_check
            check (kind in ('embedding', 'reranker'));
    end if;

    -- An embedding model has a dimension; a reranker does not. Enforcing the
    -- pairing keeps a reranker from being silently used as a vector space.
    if not exists (
        select 1 from pg_constraint
         where conname = 'retrieval_models_dim_kind_check'
           and conrelid = 'retrieval_models'::regclass
    ) then
        alter table retrieval_models
            add constraint retrieval_models_dim_kind_check
            check (
                (kind = 'embedding' and dim is not null and dim > 0)
                or (kind = 'reranker' and dim is null)
            );
    end if;
end $$;

create index if not exists idx_retrieval_models_active
    on retrieval_models (kind, model_id)
    where active;

-- ---------------------------------------------------------------------------
-- 3. Registration helpers
-- ---------------------------------------------------------------------------

create or replace function cg_register_retrieval_model(
    model_id_in text,
    kind_in     text,
    provider_in text,
    repo_in     text,
    revision_in text,
    dim_in      int default null
)
returns void as $$
begin
    insert into retrieval_models (model_id, kind, provider, repo, revision, dim, active)
         values (model_id_in, kind_in, provider_in, repo_in, revision_in, dim_in, true)
    on conflict (model_id) do update
       set kind     = excluded.kind,
           provider = excluded.provider,
           repo     = excluded.repo,
           revision = excluded.revision,
           dim      = excluded.dim,
           active   = true;
end;
$$ language plpgsql;

-- Deactivation is not deletion: a retired model must stay resolvable, because
-- vectors and rankings produced by it remain in the database and stay
-- attributable only while its row survives.
create or replace function cg_deactivate_retrieval_model(model_id_in text)
returns void as $$
begin
    update retrieval_models set active = false where model_id = model_id_in;
end;
$$ language plpgsql;

-- ---------------------------------------------------------------------------
-- 4. Seed from the existing embedding_models rows
-- ---------------------------------------------------------------------------

-- Provenance is unknown for models registered before this migration, so the
-- placeholder is explicit rather than invented. A deployment that knows its
-- upstream should call cg_register_retrieval_model() to overwrite it; the
-- parity view in 035 reports rows still carrying it.
insert into retrieval_models (model_id, kind, provider, repo, revision, dim, active)
select em.model_id,
       'embedding',
       'unrecorded',
       'unrecorded',
       'unrecorded',
       em.dim,
       em.deprecated_at is null
  from embedding_models em
 where em.dim is not null
on conflict (model_id) do nothing;
