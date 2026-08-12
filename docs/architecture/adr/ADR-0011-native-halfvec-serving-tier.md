# ADR-0011: Native halfvec serving tier

## Status

Accepted (recorded 2026-08-12). Resolves ADR-0010 open questions 1 and 2.
Supersedes the storage half of migration 021, which is left in place rather
than reverted (see Consequences).

## Context

ADR-0010 compared this repository against `axiom_kg` and left two questions
open, both deferred because they change retrieval behaviour and not just
schema. The maintainer has since directed that axiom be treated as the
reference configuration for this decision, which settles both.

**Question 1 — should the serving tier move to a native-halfvec
`(subject, model)` table?** Migration 021 put `embedding vector(N)` and a
trigger-derived `embedding_half halfvec(N)` on one table, and built an HNSW
index over each, per model. That is two copies of every vector and two graphs
per model. Measured on axiom: 12.7 kB/row for the equivalent dual-column table
against 2.8 kB/row for the halfvec-only serving table.

**Question 2 — should the HNSW indexes be scoped to `where retrieval_active`?**
Framing it as an index predicate was the wrong shape. axiom does not predicate
its index; its serving table simply contains no cold rows. 176,235 documents
against 51,100 vector rows per model, and the index is small because the table
is small. A predicate would have shrunk the index while leaving the heap to
grow, which is the worse half of the trade.

## Decision

- **Add `retrieval_embeddings`** (migration 036), mirroring axiom's table:
  `graph_id`, `model_id`, `embedding halfvec(N)`, `created_at`, primary key
  `(graph_id, model_id)`, one partial HNSW index per model over
  `halfvec_cosine_ops`.

- **Mirror faithfully, including the omissions.** No full-precision twin, and
  no `tlp_level`; axiom keeps TLP on its legacy `embeddings`, not on the
  serving tier. Copying a reference configuration means copying what it leaves
  out, or the comparison stops being evidence.

- **Populate only retrieval-active subjects.** This is the mechanism behind
  question 2, and it is why no index predicate is needed.

- **Derive the dimension from `embeddings.embedding`** via `pg_attribute`, the
  way 021 does, so the two cannot drift.

- **Repoint `_vector_candidates` at the serving tier**, with the ANN in its own
  CTE carrying its own `order by` and `limit` directly against the indexed
  table. Joining first and ordering afterwards leaves the planner unable to use
  the HNSW index — a silent performance cliff rather than an error.

- **Resolve `model_id` to a concrete model before querying.** It was optional,
  and `None` meant no filter. With per-model partial indexes that is both slow
  (no index is applicable) and wrong (it mixes vector spaces that are not
  comparable). The function already refused cross-model retrieval, so the
  process default is the only thing `None` could have meant.

## Consequences

Positive. One vector per subject per model instead of two, one HNSW graph per
model instead of two, and the vector tier is bounded by the hot set rather than
by total corpus. The ANN can no longer accidentally span vector spaces.

Negative. `embeddings.embedding_half` and 021's halfvec indexes are now dead
weight: nothing reads them. They are deliberately **not** dropped here. Keeping
them makes this change reversible by pointing `_vector_candidates` back at
`embeddings`, which matters because the retrieval-quality effect of moving to
half precision is **not** measured anywhere yet. See the correction below.
Dropping them is a follow-up once something does measure it.

Neutral. `embeddings` is unchanged and remains the identity and full-precision
record for every subject, hot or cold, exactly as axiom keeps its own legacy
pair.

Worth knowing for anyone writing a migration here: migration 001 sets the
database `search_path` to `ag_catalog,"$user",public`, so an unqualified
`CREATE TABLE` in a migration lands in **`ag_catalog`**, not `public`. That is
where `embeddings`, `retrieval_models` and now `retrieval_embeddings` actually
live. Everything resolves consistently through the search path, so it works,
but a guard written as `to_regclass('public.<table>')` asks a different
question than the unqualified `CREATE` answers: it reports NULL on a re-run
even though the table exists, and the migration then fails as "relation already
exists" on the idempotency pass rather than the first one.
`tests/rls/test_tlp_enforcement.sql` documents the same trap for its own
stand-in table. The guard in 036 is deliberately unqualified for this reason.

It then caught 037's test from the opposite direction, which is worth recording
because the two failures look nothing alike. 036 over-qualified
(`to_regclass('public.…')` on a table that is not in public);
`tests/rls/test_vector_tlp.sql` under-qualified, by opening with
`set search_path = public` copied from `test_tlp_enforcement.sql` — correct
there, because that suite creates its own stand-in and wants it in public, and
wrong for any suite touching the real tables, which vanish. A third form exists
and is worse than both: a non-superuser role without `USAGE` on the holding
schema gets "relation does not exist" rather than zero rows, so a suite that
does not assert on visible-row counts would pass vacuously. Anything new that
touches these tables should resolve the schema from `pg_class` rather than
assume one.

## Correction (2026-08-12, same day)

This ADR as first written claimed the eval gate "runs in CI against real data"
and would show whether halfvec-only retrieval changed result quality. **That is
false**, and the claim was load-bearing for the decision to keep 021's columns
as a rollback path.

`scripts/eval/run_retrieval_eval.py` requires an embedding provider to embed
each golden query. CI runs with `CG_EMBEDDING_PROVIDER=none`, so the script
emits `status: "skipped_no_embedding_provider"` and exits 0. The
`retrieval-eval` job is therefore green without having evaluated anything.

That skip is deliberate and documented in the header of
`.github/workflows/eval.yml`: "Without an embedding backend
(`CG_EMBEDDING_PROVIDER=none` in CI) the retrieval/drift steps skip cleanly;
the unit-test layer covers the pure helpers." The design is sound. The error
was this ADR asserting a verification that the workflow it depends on says it
does not perform.

Two consequences follow.

**Nothing measured the half-precision change.** Moving from `vector` to
`halfvec` is a precision reduction and could plausibly cost recall. That effect
remains unmeasured. It is the reason 021's columns stay: not "until the gate
runs", but until something measures it at all. A meaningful measurement needs a
real embedding model, because a deterministic stub embedder produces vectors
with no semantic structure and recall numbers computed over it would be noise.

**A second gate is inert for the same reason, and that one is not documented.**
`tests/eval/test_rls_retrieval_correctness.py` asserts that `vector_search`
never returns a document above the caller's TLP ceiling and describes itself as
"a **hard CI fail** if RLS regresses". It skips when no embedding provider is
configured, which in CI is always. It is the test that would have caught the
TLP gap described in the next section, and it has never run.

Unlike the quality eval, this one does not need semantic embeddings: it asserts
only that nothing above the ceiling comes back, which holds for any vector
whatsoever. It also needs the database populated from the golden set, and
nothing in the repository does that.

## Discovered while implementing: the vector path does not enforce TLP

Not caused by this change, and not fixed by it, but found in the course of it
and recorded here because it bears directly on the retrieval path.

RLS in this repository is applied only to `core_graph.*` tables, dynamically,
by migrations 004, 010, 022 and 028. `public.embeddings` has no policy, and
neither does `retrieval_embeddings`. `get_connection()` sets `app.max_tlp` and
`app.allowed_compartments`, but those GUCs are read by policies that exist only
on the graph tables, so they do not constrain a query against `embeddings`.
`hybrid_search()` performs no post-filter either: `caller_identity` reaches the
connection and the audit row, and nothing else.

The consequence is that `hybrid_search` returns `content` for any subject whose
text was embedded, at any TLP level, to any caller. That contradicts "Row-Level
Security enforces TLP markings at the engine level" as stated in the project
conventions.

Deliberately out of scope for this ADR. Adding RLS to a table on the hot
retrieval path is a security-behaviour change that needs its own decision, its
own `tests/rls/` suite, and a write-path policy so ingest is not locked out —
the same treatment 028 gave the graph tables. Raised for a separate decision.

**Severity is bounded today by a second gap.** Nothing in this repository writes
`embeddings`. There is no `insert into embeddings` in `api/`, `ingest/`,
`evidence/` or `scripts/`; `ingest/graph_writer.py` contains no vector
reference at all; and `generate_embedding()` is called from exactly two places,
both to embed the *query* rather than to persist a document vector. The vector
tier has a complete read path and no producer, so in a deployment fed only by
this repository the table is empty and there is nothing to leak.

That makes the TLP gap latent rather than live, and it makes fixing it cheap
right now: with no rows, a fail-closed default costs nothing and needs no
backfill. It becomes expensive the moment a writer exists. The ordering
argument is therefore to close it before building the producer, not after.

Whether an out-of-tree producer already populates the table in a given
deployment is not knowable from the repository; axiom has one
(`graph/extract_graph.py`) for `axiom_kg`, and this repository may be intended
to acquire the equivalent.

## Alternatives considered and rejected

**Predicating 021's existing indexes on `retrieval_active`.** The literal
reading of ADR-0010 question 2. Rejected once axiom showed the alternative:
the table itself carries only hot rows, so the heap shrinks too.

**Dropping `embedding` and `embedding_half` in the same migration.** Rejected
for reversibility. The eval gate is what will show whether halfvec-only
retrieval changes result quality, and it runs in CI against real data; keeping
the old columns means the rollback is a one-line query change.

**Carrying `tlp_level` on the serving table anyway.** Tempting given the gap
above, and the column would have been cheap. Rejected because it is not what
the reference configuration does, and because an unenforced column invites the
belief that something is enforced.

## Revisit triggers

- An embedding provider becoming available to CI or to a scheduled run, which
  would let the quality eval measure the half-precision change for the first
  time. A regression there is the trigger to point `_vector_candidates` back at
  `embeddings.embedding`.
- A producer being added for `embeddings`. That converts the TLP gap from
  latent to live and should not land before the gap is closed.
- A second embedding model at a different dimension, which the shared
  `halfvec(N)` column still cannot express; the `(graph_id, model_id)` key
  makes a partitioned or per-model-table follow-up straightforward.
- A decision on the TLP gap above.

## References

- ADR-0010 (reconciliation with axiom_kg), open questions 1 and 2.
- Live `axiom_kg` introspection, 2026-08-12.
- Migration 021 (embedding models and hybrid), migration 036.
