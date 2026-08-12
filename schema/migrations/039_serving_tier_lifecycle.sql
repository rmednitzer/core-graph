\echo 'applying 039_serving_tier_lifecycle.sql'
-- 039_serving_tier_lifecycle.sql
-- What maintains the serving tier, and what writes the lifecycle columns.
--
-- Closes ADR-0010 open question 3, and fixes a defect introduced by 036 while
-- answering it.
--
-- THE DEFECT. Migration 012 schedules `stale-embedding-cleanup`, which deletes
-- daily from `embeddings` for vertices that no longer exist in the graph. 036
-- added `retrieval_embeddings` as a second copy of the vector and gave it no
-- delete path at all: it only ever inserts. So every row 012 removes leaves a
-- serving row behind permanently.
--
-- That is not inert. `_vector_candidates` picks top-k from
-- `retrieval_embeddings` in a CTE and joins `embeddings` afterwards, which is
-- what makes the HNSW index usable. An orphan wins a slot in the CTE and is
-- then dropped by the join, so the caller asks for k candidates and silently
-- receives fewer. It is exactly the under-return failure migration 027 enabled
-- iterative scans to prevent, reintroduced through a different door, and it
-- degrades as the graph churns rather than showing up at once.
--
-- No foreign key can express the link. `embeddings` is keyed on a surrogate
-- `id bigserial` (003) and carries only a non-unique index on `graph_id` (003)
-- and another on `model_id` (021). There is no unique constraint on
-- `graph_id`, on `model_id`, or on the pair, so there is nothing for
-- `retrieval_embeddings.graph_id` to reference.
--
-- Adding one is possible and tempting, and this migration deliberately does
-- not. A `unique (graph_id, model_id)` would fail outright on any deployment
-- whose out-of-tree producer has ever inserted a re-embedding rather than
-- updating in place, and the only way to make it succeed would be to delete
-- rows from `embeddings`. A migration that silently destroys embedded content
-- to satisfy a constraint is worse than the defect it fixes. The trigger below
-- achieves the same pruning without requiring uniqueness, and
-- `cg_serving_tier_duplicates` reports the condition so an operator can decide.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Prune the orphans that already exist
-- ---------------------------------------------------------------------------

-- One-shot for deployments that have been running 012 since 036 landed. On a
-- fresh chain this matches nothing.
delete from retrieval_embeddings re
 where not exists (
     select 1 from embeddings e
      where e.graph_id = re.graph_id
        and e.model_id = re.model_id
 );

-- ---------------------------------------------------------------------------
-- 2. Keep them from coming back
-- ---------------------------------------------------------------------------

-- Statement-level, with a transition table, rather than FOR EACH ROW. 012's
-- cleanup deletes in bulk, and a row-level trigger would issue one statement
-- per deleted row against a table carrying an HNSW index.
--
-- The `not exists` re-check is what makes this correct without a unique key:
-- if another `embeddings` row still holds the same (graph_id, model_id) the
-- subject is still embedded and its serving row must stay.
create or replace function cg_prune_serving_tier()
returns trigger
language plpgsql
as $fn$
begin
    delete from retrieval_embeddings re
     using deleted d
     where re.graph_id = d.graph_id
       and re.model_id = d.model_id
       and not exists (
           select 1 from embeddings e
            where e.graph_id = d.graph_id
              and e.model_id = d.model_id
       );
    return null;
end;
$fn$;

comment on function cg_prune_serving_tier() is
    'AFTER DELETE ON embeddings: removes the matching serving-tier row once no '
    'embeddings row holds that (graph_id, model_id) any more. Stands in for the '
    'ON DELETE CASCADE that cannot be declared, because embeddings has no '
    'unique key on the pair.';

drop trigger if exists trg_embeddings_prune_serving on embeddings;
create trigger trg_embeddings_prune_serving
    after delete on embeddings
    referencing old table as deleted
    for each statement execute function cg_prune_serving_tier();

-- On RLS, which decides whether this is complete or best-effort. A trigger
-- function runs as the invoking user, not the owner, so its DELETE against
-- `retrieval_embeddings` is subject to 037's `tlp_write_delete` policy whenever
-- the invoker is not the owner. Under a session with a low `app.max_tlp` the
-- prune would skip exactly the orphans above that ceiling.
--
-- It is complete today, because the only thing that deletes from `embeddings`
-- is 012's pg_cron job, which runs as the identity that scheduled it: the
-- migration runner, which owns the table, and 037 enabled RLS without forcing
-- it. Nothing else deletes, because nothing writes `embeddings` at all
-- (ADR-0011).
--
-- Left as SECURITY INVOKER rather than pre-empting that with SECURITY DEFINER,
-- which would add a privilege-escalation surface to defend against a caller
-- that does not exist. A producer that deletes as `cg_app` is the trigger to
-- revisit; see ADR-0013.

-- ---------------------------------------------------------------------------
-- 3. Report the condition no constraint is enforcing
-- ---------------------------------------------------------------------------

create or replace view cg_serving_tier_duplicates as
select graph_id, model_id, count(*) as copies
  from embeddings
 where model_id is not null
 group by graph_id, model_id
having count(*) > 1;

comment on view cg_serving_tier_duplicates is
    'Subjects embedded more than once under the same model. Not an error, but '
    'the serving tier holds one row per pair, so only one of them is ever '
    'served, and `_vector_candidates` picks the newest by embeddings.id. '
    'Non-empty here is what blocks a unique (graph_id, model_id) constraint.';

-- ---------------------------------------------------------------------------
-- 4. Reconcile the serving tier against the source of truth
-- ---------------------------------------------------------------------------

-- 036's backfill was a one-shot INSERT inside the migration. Making it a
-- re-runnable function that also removes is what turns `retrieval_active` from
-- a column nothing reads into the thing that decides the hot set, which is the
-- property ADR-0011 claims for the serving tier.
create or replace function cg_sync_serving_tier()
returns table (removed bigint, added bigint)
language plpgsql
as $fn$
declare
    n_removed bigint;
    n_added   bigint;
begin
    -- Subjects that went cold, or whose model changed under them.
    with gone as (
        delete from retrieval_embeddings re
         where not exists (
             select 1 from embeddings e
              where e.graph_id = re.graph_id
                and e.model_id = re.model_id
                and e.retrieval_active
         )
        returning 1
    )
    select count(*) into n_removed from gone;

    -- Subjects that are active and have a vector but no serving row. Mirrors
    -- 036's backfill predicate exactly, so the two cannot drift. Note what that
    -- means: like 036, it does not filter on `rm.active`, so a deactivated
    -- model keeps its serving rows. Retiring a model's vectors is
    -- cg_deactivate_retrieval_model()'s job (034), not this one.
    with fresh as (
        insert into retrieval_embeddings (graph_id, model_id, embedding, tlp_level)
        select e.graph_id, e.model_id, e.embedding_half, e.tlp_level
          from embeddings e
          join retrieval_models rm
            on rm.model_id = e.model_id
           and rm.kind = 'embedding'
         where e.retrieval_active
           and e.embedding_half is not null
           and e.model_id is not null
        on conflict (graph_id, model_id) do nothing
        returning 1
    )
    select count(*) into n_added from fresh;

    return query select n_removed, n_added;
end;
$fn$;

comment on function cg_sync_serving_tier() is
    'Reconciles retrieval_embeddings against the retrieval-active half of '
    'embeddings, in both directions. Re-runnable; migration 036 performed the '
    'insert half once.';

-- ---------------------------------------------------------------------------
-- 5. Write the lifecycle columns
-- ---------------------------------------------------------------------------

-- ADR-0010 question 3. axiom runs a 45-day rolling window over feed material
-- with pinned rows exempt, which is the shape mirrored here.
--
-- Two independent expiry paths, matching the two columns 035 added:
--   * `expires_at` is the per-row override. It applies whatever the retention
--     class, because a producer that set an explicit date meant it.
--   * the rolling window applies to `retention_class = 'hot'` only.
--
-- `pinned` exempts a row from both. 035 already enforces at the constraint
-- level that a pinned row carries no `expires_at`; this is the other half.
--
-- INERT BY DEFAULT, and deliberately so. 035 defaults every row to
-- `retention_class = 'durable'` with a null `expires_at`, so on any existing
-- deployment this function matches nothing until a producer classifies rows.
-- Classifying them is a product decision about which subjects are feed
-- material, not a schema one, and ADR-0010 recorded it as such. What was
-- missing was the mechanism, not the policy.
create or replace function cg_expire_retrieval(retention_window interval default '45 days')
returns bigint
language plpgsql
as $fn$
declare
    n bigint;
begin
    if retention_window <= interval '0' then
        raise exception 'retention_window must be positive, got %', retention_window;
    end if;

    with expired as (
        update embeddings
           set retrieval_active = false
         where retrieval_active
           and not pinned
           and (
                   (expires_at is not null and expires_at <= now())
                or (retention_class = 'hot' and created_at < now() - retention_window)
               )
        returning 1
    )
    select count(*) into n from expired;

    return n;
end;
$fn$;

comment on function cg_expire_retrieval(interval) is
    'Marks retrieval-inactive any unpinned subject past its expires_at, or any '
    'unpinned hot-class subject older than the rolling window. Does not delete: '
    'the row stays queryable relationally and loses only its vector, once '
    'cg_sync_serving_tier() runs.';

-- ---------------------------------------------------------------------------
-- 6. Drive them
-- ---------------------------------------------------------------------------

-- One entry point rather than two schedules. Expiry has to run before the sync
-- or the subjects it just cooled keep their vectors for another day, and two
-- cron entries would encode that ordering as a gap between two clock times.
create or replace function cg_retrieval_maintenance(retention_window interval default '45 days')
returns table (expired bigint, removed bigint, added bigint)
language plpgsql
as $fn$
declare
    n_expired bigint;
begin
    n_expired := cg_expire_retrieval(retention_window);
    return query select n_expired, s.removed, s.added from cg_sync_serving_tier() s;
end;
$fn$;

comment on function cg_retrieval_maintenance(interval) is
    'Expiry then reconciliation, in that order. The pg_cron entry calls this.';

-- 03:00 is 012's stale-embedding-cleanup, whose deletes now fire the prune
-- trigger. Running after it means the sync sees the post-cleanup state rather
-- than reconciling against rows that are about to disappear.
select cron.schedule(
    'retrieval-maintenance',
    '30 3 * * *',
    $$select cg_retrieval_maintenance()$$
);
