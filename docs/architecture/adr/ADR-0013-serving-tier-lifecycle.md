# ADR-0013: Serving-tier lifecycle

## Status

Accepted (recorded 2026-08-12). Resolves ADR-0010 open question 3, and fixes a
defect introduced by migration 036 under ADR-0011.

## Context

ADR-0011 moved retrieval onto `retrieval_embeddings`, a native-halfvec serving
table holding one vector per `(graph_id, model_id)` for retrieval-active
subjects only. The argument for it was that the HNSW graph stays small because
the table stays small.

Two things were missing for that to be true, and one of them was a live defect.

**The serving tier had no delete path.** Migration 036 only ever inserts.
Migration 012 schedules `stale-embedding-cleanup`, which deletes from
`embeddings` daily for graph vertices that no longer exist. Every row it removes
left a serving row behind permanently.

That is not cosmetic. `_vector_candidates` takes top-k from
`retrieval_embeddings` in a CTE and joins `embeddings` afterwards, which is the
shape that lets the planner use the HNSW index. An orphan wins a slot in the CTE
and is then dropped by the join, so a caller asking for k candidates silently
receives fewer. It is the under-return failure migration 027 enabled iterative
scans to prevent, reintroduced through a different door, and it worsens with
graph churn rather than appearing at once.

**Nothing wrote the lifecycle columns.** Migration 035 added
`retrieval_active`, `pinned`, `expires_at` and `retention_class`, defaulting
every row to active and durable, and ADR-0010 recorded "what writes them?" as an
open question. Until something does, every subject is permanently hot and the
serving table is the whole corpus, which is exactly the property ADR-0011
claimed it would not have.

**A third thing surfaced while fixing the first.** `embeddings` is keyed on a
surrogate `id bigserial` (003) and carries only non-unique indexes on `graph_id`
(003) and `model_id` (021). There is no unique constraint on `graph_id`, on
`model_id`, or on the pair. So no foreign key from `retrieval_embeddings` is
expressible, and the plain join in `_vector_candidates` can fan out: a subject
embedded twice under the same model multiplies its ANN candidate, and the caller
gets more than `limit` rows with duplicate `graph_id`s.

## Decision

**A statement-level `AFTER DELETE` trigger on `embeddings`**, not a foreign key.
It removes the serving row once no `embeddings` row holds that
`(graph_id, model_id)` any more. Statement-level with a transition table because
012's cleanup deletes in bulk and a row-level trigger would issue one statement
per row against a table carrying an HNSW index.

**Do not add `unique (graph_id, model_id)` to `embeddings`.** It is the obvious
fix and it is the wrong one here. The constraint would fail outright on any
deployment whose out-of-tree producer has ever inserted a re-embedding rather
than updating in place, and the only way to make it succeed would be to delete
rows from `embeddings`. A migration that destroys embedded content to satisfy a
constraint is worse than the defect it fixes. The `not exists` re-check in the
trigger achieves the pruning without uniqueness, and the new
`cg_serving_tier_duplicates` view reports the condition so an operator can
decide.

**Fix the fan-out in the query instead**, with a `LATERAL … ORDER BY id DESC
LIMIT 1` in place of the plain join. Exactly one hydration row per ANN
candidate, whether or not duplicates exist, resolving to the newest embedding.

**`cg_sync_serving_tier()` reconciles both directions** — removes serving rows
for subjects that went cold, adds them for active subjects that have a vector
and no serving row. Migration 036's backfill was a one-shot `INSERT` inside the
migration; making it a re-runnable function that also removes is what turns
`retrieval_active` from a column nothing reads into the thing that decides the
hot set.

**`cg_expire_retrieval(interval)` writes the lifecycle columns**, mirroring
axiom: a 45-day rolling window over `retention_class = 'hot'`, with `pinned`
exempt and `expires_at` as a per-row override that applies whatever the class.
It marks rows inactive; it does not delete. The row stays queryable relationally
and loses only its vector, once the sync runs.

**One `pg_cron` entry, not two.** `cg_retrieval_maintenance()` calls expiry then
reconciliation. Two schedules would encode that ordering as a gap between two
clock times. It runs at 03:30, after 012's 03:00 cleanup, so the sync sees the
post-cleanup state.

## Consequences

Positive. Retrieval stops silently under-returning as the graph churns, and it
can no longer over-return through duplicate hydration. The serving table is now
bounded by the hot set in fact rather than by assertion, which is what ADR-0011
assumed. `retrieval_active` is load-bearing for the first time.

Negative, and worth being plain about: **the sweeper is inert by default.** 035
defaults every row to `durable` with a null `expires_at`, so
`cg_expire_retrieval()` matches nothing until a producer classifies rows.
Deciding which subjects are feed material is a product decision, not a schema
one, and ADR-0010 recorded it as such. What was missing was the mechanism, not
the policy. Anyone reading this as "retention is now enforced" would be wrong;
what is enforced is that a classified row ages out correctly.

The prune trigger, by contrast, is live immediately: it needs no classification
and fires on the deletes 012 already performs.

Neutral. `embeddings` remains the full-precision record for every subject, hot
or cold. Expiry never deletes content.

## The RLS caveat

A trigger function runs as the invoking user, not the owner, so the prune's
`DELETE` against `retrieval_embeddings` is subject to 037's `tlp_write_delete`
policy whenever the invoker is not the owner. Under a session with a low
`app.max_tlp` it would skip exactly the orphans above that ceiling.

It is complete today because the only thing that deletes from `embeddings` is
012's `pg_cron` job, which runs as the identity that scheduled it — the
migration runner, which owns the table — and 037 enabled RLS without forcing it.
Nothing else deletes, because nothing writes `embeddings` at all (ADR-0011).

Left as `SECURITY INVOKER` rather than pre-empting that with `SECURITY DEFINER`,
which would add a privilege-escalation surface to defend against a caller that
does not exist. Noted as a revisit trigger below.

## Alternatives considered and rejected

**`unique (graph_id, model_id)` plus `ON DELETE CASCADE`.** The clean
declarative answer, rejected on the data-destruction argument above. If an
operator confirms `cg_serving_tier_duplicates` is empty for their deployment,
adding it later is a one-line migration and the trigger becomes redundant rather
than wrong.

**A row-level trigger.** Simpler to read, and wrong for the workload: 012's
cleanup is a bulk delete.

**Deleting expired rows from `embeddings` outright**, as a true retention
policy. Rejected because `embeddings` carries `content` and the audit trail
treats it as evidence; ageing out a vector is reversible from the full-precision
column, deleting the row is not. 012 already deletes, but only for subjects
whose graph vertex is gone.

**Two `pg_cron` entries.** Rejected on the ordering argument.

## Revisit triggers

- A producer being added for `embeddings`, especially one that deletes as
  `cg_app` rather than as the owner. That is when the prune trigger's
  `SECURITY INVOKER` posture stops being sufficient.
- `cg_serving_tier_duplicates` being confirmed empty on every deployment, which
  makes the unique constraint and a real foreign key available.
- A classification rule for `retention_class`, which is what makes the sweeper
  do anything.
- A window other than 45 days. It is a function argument, not a constant, so
  changing it is a change to the `cron.schedule` command rather than a
  migration.

## References

- ADR-0010 open question 3; ADR-0011 (the serving tier).
- Migrations 003 (surrogate key), 012 (stale-embedding-cleanup), 021,
  035 (lifecycle columns), 036 (serving tier), 037 (vector-tier RLS), 039.
- `tests/schema/test_retention.py`.
