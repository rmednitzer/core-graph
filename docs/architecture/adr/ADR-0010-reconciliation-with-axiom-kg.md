# ADR-0010: Reconcile the retrieval tier against axiom_kg

## Status

Accepted (recorded 2026-08-12). Extends ADR-0002 (hybrid retrieval) with the
model registry and lifecycle it left out. Supersedes nothing.

## Context

`axiom_kg` is a running instance of the design this repository targets:
PostgreSQL with Apache AGE and pgvector, hybrid lexical plus dense retrieval,
reranking, and an entity-resolving ingest path. It has been in production since
2026-07-02. This ADR records a direct comparison against it, and adopts three
things it does that this repository does not.

Verified against the live database on 2026-08-12 (read-only introspection via
the Vertex control plane; every figure below was measured, not estimated):

| | axiom_kg | core-graph |
|---|---|---|
| PostgreSQL | 18.4 | 18 (CI runs the same major) |
| Extensions | age, vector, pg_cron, pgaudit, pgcrypto, pg_trgm, pg_stat_statements, amcheck | age, vector, pg_cron, pgaudit, pgcrypto, btree_gist |
| Documents | 176,235 | n/a |
| Retrieval-active | 51,100 (29%) | no such concept |
| Vector rows | 102,200 (51,100 x 2 models) | one row per subject per model |
| Vector type | `halfvec(512)`, native | `vector(768)` plus derived `halfvec(768)` |
| Model registry | `retrieval_models` (kind, provider, repo, revision, dim, active) | `embedding_models` (model_id, dim, deprecated_at) |
| Rerankers | 2, registered rows | `CG_RERANKER_URL`, no registry row |
| Parity tracking | per-model gap, held at 0 | none |

Three gaps follow from that table.

**Provenance.** `embedding_models` records a dimension and nothing else. It
cannot express a reranker at all, and it records nothing about which weights
produced a given vector. `api/mcp/tools/hybrid_search.py` reranks through
`CG_RERANKER_URL`, an environment variable, so a reranked result set is not
attributable to any artifact. axiom registers both rerankers as rows carrying
`provider`, `repo` and an exact upstream `revision`, which is what makes a
stored vector or a recorded ranking auditable after the fact. For a platform
whose stated target is "auditable, evidence-producing", an unattributable
ranking is a real gap rather than a tidiness one.

**Lifecycle.** Every row in `embeddings` here is permanently live. axiom keeps
176,235 documents and only 51,100 of them retrieval-active, a rolling hot tier
with an explicit pin. That is what holds the database to 5,080 MB and keeps the
HNSW graphs small enough to stay resident. Without the distinction this
repository's vector tier grows without bound, and nothing can be aged out
without deleting evidence, which the append-only posture forbids.

**Parity.** axiom reports a per-model gap and holds it at zero: 51,100 vectors
in each of the two active spaces. If one space covers less of the corpus than
another, hybrid fusion silently searches a smaller corpus on one side and the
blend shifts, with no error raised anywhere. Nothing here measured that.

`pg_trgm` is a fourth, smaller gap: `ingest/resolver/` does entity resolution
with no trigram index available to it.

## Decision

- **Add `retrieval_models` as a separate table** (migration 034), mirroring
  axiom's shape: `kind` in (`embedding`, `reranker`), `provider`, `repo`,
  `revision`, nullable `dim`, `active`. `revision` is the load-bearing column;
  it pins an immutable upstream commit rather than a moving tag.

  It is a new table rather than columns on `embedding_models` because
  `make migrate` replays every migration on every run. Migration 021 ends by
  calling `cg_create_model_indexes()` over every non-deprecated
  `embedding_models` row, and that function raises when `dim` is null. A
  nullable-dim reranker row in `embedding_models` would therefore break the
  *second* replay of 021 — and 021 also re-creates the function, so hardening
  it from a later migration would be overwritten. A separate table removes the
  ordering hazard. This is also why axiom has both tables.

- **Pair `dim` with `kind` by check constraint.** An embedding model has a
  positive dimension; a reranker has none. Enforcing the pairing stops a
  reranker being used as a vector space.

- **Deactivation is not deletion.** Vectors produced by a retired model stay
  attributable only while its row survives, so `cg_deactivate_retrieval_model`
  sets `active = false` and keeps the row.

- **Add lifecycle columns to `embeddings`** (migration 035): `retrieval_active`,
  `pinned`, `expires_at`, `retention_class`. Defaults make every existing row
  durable and active, so applying the migration changes no retrieval behaviour
  until something sets them. A pinned row may not carry an expiry, enforced by
  constraint rather than left to sweeper logic.

- **Add `cg_retrieval_parity`**, reporting active subjects, vectors present and
  the gap per active embedding model. Rerankers are excluded; counting them
  would report a permanent phantom gap.

- **Add `pg_trgm`.**

- **Backfill provenance as an explicit placeholder,** not an invention. Models
  registered before 034 get `unrecorded` for provider/repo/revision, and
  `cg_retrieval_models_unrecorded` keeps that debt visible.

## Consequences

Positive. A ranking becomes attributable to specific model weights. The vector
tier gains the vocabulary for a bounded hot tier. Silent corpus asymmetry
between vector spaces becomes a number someone can alert on. The resolver gains
trigram support.

Negative. Two model tables now exist, and the split needs the explanation above
to make sense. `embedding_models` remains the FK target for
`embeddings.model_id`; `retrieval_models` is the provenance surface. Nothing
yet writes the lifecycle columns, so 035 adds vocabulary ahead of the sweeper
that will use it.

Neutral. Both migrations are additive and idempotent; both were replayed three
times against PostgreSQL 16 during development with no drift. The dev stack
runs 18, so the replay used a fixture standing up only the objects 034 and 035
touch, because `age` and `vector` are unavailable on 16.

## Alternatives considered and rejected

**Columns on `embedding_models` instead of a new table.** Rejected for the
replay hazard above; discovered by tracing what `make migrate` does on a second
run rather than a first.

**Copy axiom's `retrieval_embeddings` table wholesale.** Rejected for now. Its
`(document_id, model_id)` key with a native `halfvec(512)` is a better shape
than this repository's `vector(768)` plus trigger-derived `halfvec(768)`, which
stores two copies of every vector and builds two HNSW graphs per model. The
measured difference on axiom is 12.7 KB/row for the legacy dual-column table
against 2.8 KB/row for the halfvec-only serving table, a factor of 4.5. But
dropping the full-precision column changes recall characteristics as well as
size, and this repository has an established migration path through 021 that a
wholesale replacement would strand. Recorded as the open question below.

**Deriving `active` from `deprecated_at`.** `embedding_models` already encodes
liveness as `deprecated_at is null`. Adding an `active` boolean to that table
would have created a second source of truth for the same fact. `retrieval_models`
is a new table with no such column, so `active` there is the only encoding.

## Open questions

1. **Should the serving tier move to a native-halfvec `(subject, model)`
   table?** The 4.5x storage measurement argues yes; the recall change and the
   migration path argue for doing it deliberately, with an eval run on the
   golden set either side. Needs `make eval` before and after.

2. **Should the per-model HNSW indexes from 021 be re-scoped to
   `where retrieval_active`?** On axiom's ratio that would drop 71% of each
   index. It also narrows recall to the hot tier, which is a product decision,
   not a schema one. 035 deliberately does not do it.

3. **What writes the lifecycle columns?** axiom runs a 45-day rolling window
   over feed material with pinned rows exempt. The equivalent here would be a
   `pg_cron` job in the style of migration 012.

## References

- Live `axiom_kg` introspection, 2026-08-12 (extensions, table inventory,
  column types, index definitions, `retrieval_models` contents, per-model
  vector counts, role inventory).
- `/opt/mcp/docs/CONTEXT-axiom.md`, "axiom_kg (knowledge graph subsystem)".
- ADR-0002 (hybrid retrieval), migration 021 (embedding models and hybrid).
