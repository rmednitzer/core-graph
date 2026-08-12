\echo 'applying 035_retrieval_lifecycle.sql'
-- 035_retrieval_lifecycle.sql
-- Retention lifecycle on `embeddings`, and a parity surface over the
-- registry added by 034.
--
-- Reconciles this repository against the live axiom_kg database. See ADR-0010.
--
-- The measured gap: axiom holds 176,235 documents and keeps 51,100 of them
-- retrieval-active, a rolling hot tier with an explicit pin escape hatch.
-- Everything else stays queryable relationally but carries no vector. That is
-- what holds the whole database to 5,080 MB while the vector tier stays small
-- enough to keep its HNSW graphs resident.
--
-- This repository has no such distinction. Every row in `embeddings` is
-- permanently live, so the vector tier and its HNSW indexes grow without bound
-- and nothing can be aged out without deleting evidence.
--
-- This migration adds the columns and the reporting surface. It deliberately
-- does NOT re-scope the per-model HNSW indexes from 021 to
-- `where retrieval_active`: that narrows recall as well as index size and is a
-- decision for the operator, recorded as the open question in ADR-0010.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Lifecycle columns
-- ---------------------------------------------------------------------------

alter table embeddings
    add column if not exists retrieval_active boolean not null default true;

alter table embeddings
    add column if not exists pinned boolean not null default false;

alter table embeddings
    add column if not exists expires_at timestamptz;

alter table embeddings
    add column if not exists retention_class text not null default 'durable';

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'embeddings_retention_class_check'
           and conrelid = 'embeddings'::regclass
    ) then
        alter table embeddings
            add constraint embeddings_retention_class_check
            check (retention_class in ('durable', 'hot'));
    end if;

    -- A pinned row is not subject to expiry. Enforcing it here means the
    -- sweeper cannot age out something an operator pinned, whatever the
    -- sweeper's own logic does.
    if not exists (
        select 1 from pg_constraint
         where conname = 'embeddings_pinned_no_expiry_check'
           and conrelid = 'embeddings'::regclass
    ) then
        alter table embeddings
            add constraint embeddings_pinned_no_expiry_check
            check (not (pinned and expires_at is not null));
    end if;
end $$;

-- Defaults above make every existing row durable and active, so applying this
-- migration changes no retrieval behaviour until something sets the columns.

create index if not exists idx_embeddings_retrieval_active
    on embeddings (retrieval_active)
    where retrieval_active;

create index if not exists idx_embeddings_expires_at
    on embeddings (expires_at)
    where expires_at is not null and not pinned;

-- ---------------------------------------------------------------------------
-- 2. Parity surface
-- ---------------------------------------------------------------------------

-- axiom reports voyage_gap and nemotron_gap and holds both at zero: every
-- retrieval-active subject has a vector in every active embedding space. A
-- non-zero gap means hybrid retrieval is silently searching a smaller corpus
-- in one space than another, which shifts fusion results without any error.
-- Nothing here measured that before.
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
       (select n from subject_total)                             as active_subjects,
       count(distinct e.graph_id)                                as vectors,
       (select n from subject_total) - count(distinct e.graph_id) as gap
  from active_models am
  left join embeddings e
         on e.model_id = am.model_id
        and e.retrieval_active
 group by am.model_id;

comment on view cg_retrieval_parity is
    'Per active embedding model: retrieval-active subjects, vectors present, '
    'and the gap between them. A non-zero gap means one vector space covers '
    'less of the corpus than another, which biases hybrid fusion silently.';

-- Models carrying the placeholder provenance seeded by 034. Surfacing them is
-- the point: an unrecorded revision cannot be audited later.
create or replace view cg_retrieval_models_unrecorded as
select model_id, kind, dim, active, created_at
  from retrieval_models
 where 'unrecorded' in (provider, repo, revision);

comment on view cg_retrieval_models_unrecorded is
    'Retrieval models whose provenance was backfilled as a placeholder by '
    'migration 034 and never replaced via cg_register_retrieval_model().';
