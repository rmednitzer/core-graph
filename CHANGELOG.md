# Changelog

All notable changes to core-graph are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning of the schema and ontology
contracts. Migrations are forward-only — see `schema/migrations/README.md`.

## Unreleased

### Phase 1 — vector layer modernisation

* Migration `021_embedding_models_and_hybrid.sql`: introduces an
  `embedding_models` registry, an FK from `embeddings.model_id`, a
  `halfvec` column populated by trigger from `embedding`, a `tsvector`
  column populated by trigger from `content`, a GIN index for BM25, and
  helper functions `cg_register_embedding_model()` /
  `cg_create_model_indexes()` that materialise per-model partial HNSW
  indexes for both full and half precision.
* `api/utils/circuit_breaker.py`: Valkey-backed `CircuitBreaker` keyed
  `cg:cb:embedding:<model_id>`; falls back to a process-local counter
  when Valkey is unreachable. Replaces the per-process breaker that
  lived inside `vector_search.py`.
* `api/mcp/tools/vector_search.py`: now optionally targets the halfvec
  column, exposes `ef_search` per call, and constrains by `model_id`.
* `api/mcp/tools/hybrid_search.py` (new): runs BM25 and vector retrieval
  in parallel-from-the-DB, fuses with RRF (`k=60`), and optionally
  invokes a reranker via `CG_RERANKER_URL`.
* `scripts/bench/bench_retrieval_recall.py` (new): per-mode recall@5/10/20,
  MRR, nDCG@10. Uses `tests/eval/golden/synthetic_v1.jsonl` (100 pairs,
  4 verticals) by default — Phase 5 ships the curated 200-pair set.
* `docs/architecture/adr/ADR-0002-hybrid-retrieval.md` documents the RRF
  decision, halfvec trade-off, and per-model partial-index strategy.

### Phase 0 — verify and fix latent bugs

* `schema/migrations/020_temporal_invariants.sql`: replaced invalid
  `ADD CONSTRAINT IF NOT EXISTS` syntax with `pg_constraint` catalog lookups
  inside `DO` blocks; added explicit backfill (`UPDATE ... WHERE ... IS NULL`)
  before promoting `mutation_actor`, `mutation_reason`, and `source` to
  `NOT NULL` so the migration is safe on tables that already contain rows.
* `schema/migrations/011_vector_dimensions.sql`: silent `TRUNCATE` is no
  longer permitted. The migration now refuses unless the operator has set
  `app.allow_embedding_truncate=true` (transaction-local). Documented the
  flag in `docs/operations/database-migration-runbook.md`.
* `api/mcp/skills/queries/asset_security_events.cypher` and
  `identity_audit_trail.cypher`: removed AGE-incompatible `+` string
  concatenation. The time threshold is now computed Python-side and bound
  as the `time_threshold` parameter (ISO-8601 string).
* `api/mcp/tools/identity_attribution.py`: writer now widens the caller's
  session compartments to include `investigation_id` before the INSERT,
  closing the write-then-read RLS visibility gap on TLP:RED edges.
* `policies/resource/threat_entity.yaml`: TLP comparisons converted from
  string `tlp_marking in [...]` to integer `tlp_level <= N`, aligning with
  the schema/RLS encoding `0..4`. Cerbos test fixtures updated.
* `api/db.py`: `statement_timeout` is now set uniformly inside
  `get_connection` from `age_query_guard.query_timeout_ms`. Removes the
  per-call override in `cypher_query.py` so REST, MCP, ingest, and TAXII
  paths all enforce the same per-role ceiling.

### Tests added

* `tests/test_cypher_template_safety.py` — static scan rejecting `+` string
  concatenation in any `*.cypher` template.
* `tests/test_threat_entity_policy_tlp.py` — rejects string TLP tokens in
  Cerbos resource policies.
* `tests/test_identity_attribution_compartments.py` — exercises the
  `_widen_compartments` helper.
* `tests/test_migration_020_safety.py` — parses 020 to assert the bug
  patterns are gone.
* `tests/test_migration_011_truncate_guard.py` — asserts the GUC guard.
* `tests/test_statement_timeout_uniformity.py` — rejects duplicated
  `statement_timeout` writes outside `api/db.py`.
