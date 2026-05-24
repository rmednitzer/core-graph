# Changelog

All notable changes to core-graph are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning of the schema and ontology
contracts. Migrations are forward-only — see `schema/migrations/README.md`.

## Unreleased

### Phase 6 — code-base validation (2026-05)

* New ADR
  `docs/architecture/adr/ADR-0006-codebase-validation-2026-05.md` records
  a full code index of the repository and a cross-check of each
  implementation against authoritative upstream documentation (Apache
  AGE, pgvector, NATS JetStream, Cerbos, SpiceDB, OASIS STIX 2.1 /
  TAXII 2.1, Sigstore cosign + Rekor, MCP Python SDK, OCSF 1.1,
  RFC 6962, RFC 3161). The ADR also enumerates the documentation
  drift surfaced during the pass and the architectural-intent gaps
  (compartment enforcement is application-layer rather than RLS;
  SpiceDB schema is defined but not in the request path; the
  `identity_attribution.yaml` policy lacks a Cerbos test fixture).
* `README.md` — repository layout corrected to reflect that the
  `schema/migrations/` directory now holds `001_` through `026_`
  (was `001_` through `019_`); added an ADRs row to the documentation
  index that links to ADR-0002 through ADR-0006 and added the
  database-migration runbook to the operations row.
* `CLAUDE.md` — the "Configuration" exceptions list now records the
  three service-internal direct `os.environ` reads found by the audit
  (`CG_RERANKER_URL`, `CG_DLQ_MAX_RETRIES`,
  `CG_PROMETHEUS_WEBHOOK_SECRET`) and the deliberate
  connector-internal config-dataclass convention.
* `docs/architecture/authorization-model.md` — status notes added to
  the Layer-2 (SpiceDB) and Layer-3 (RLS) sections distinguishing the
  documented target state from currently implemented enforcement. The
  TLP policy is implemented at the engine level; the compartment
  policy is currently enforced at the Cypher template layer rather
  than via RLS.
* `docs/skills/README.md` — skill table extended with the three Phase-4
  graphrag skills (`graphrag_anchored_retrieval`, `graphrag_path_ranking`,
  `graphrag_neighborhood`) that were registered in `api/mcp/skills/graphrag/`
  but not previously listed.
* `docs/architecture/database-optimization-report.md` — appendix added
  summarising the schema-layer findings of the 2026-05 pass.

No code or schema changes — this phase is documentation only.

### Phase 5 — eval harness

* `tests/eval/golden/retrieval_v1.jsonl` (200 hand-curated query/doc
  pairs) covers `threat_intel`, `osint`, `identity`, `audit`, and
  `infrastructure` verticals across TLP levels 0..4.
* `scripts/eval/run_retrieval_eval.py`: per-mode (vector, hybrid,
  hybrid+rerank) recall@5/10/20, MRR, nDCG@10, with per-category and
  per-TLP-level breakdowns. Emits both JSON (stdout) and a markdown
  report (`--report-md`).
* `tests/eval/test_rls_retrieval_correctness.py`: hard-fail integration
  test asserting that for every TLP level a caller cannot retrieve a
  document above their ceiling, and that expected high-TLP docs are
  invisible to low-TLP callers.
* `scripts/bench/embedding_drift.py`: nightly drift detector. Pulls a
  10k-row random sample, builds a 50-bin histogram of per-row mean
  embedding values, computes KL divergence vs the stored baseline.
  WARN > 0.1, ERROR > 0.5; exits 2 on ERROR (CI fails). Emits the KL
  value as the `cg_embedding_drift_kl` Prometheus gauge added in
  `ingest/metrics.py`.
* `.github/workflows/eval.yml`: nightly job (03:17 UTC) that applies
  migrations + seeds, runs the retrieval eval, the RLS correctness
  test, and the drift detector. Reports are uploaded as workflow
  artifacts. Manually triggerable via `workflow_dispatch`.
* `tests/test_eval_runner.py`, `tests/test_embedding_drift.py` cover
  the pure helpers (golden loader, aggregation, KL formula, histogram
  binning, threshold constants).

### Phase 4 — GraphRAG skills

* New skill package `api/mcp/skills/graphrag/`:
  * `graphrag_anchored_retrieval` — hybrid_search candidate set,
    optionally constrained to an anchor entity's N-hop neighbourhood,
    re-ranked by `0.6*hybrid + 0.2*centrality + 0.2*recency`.
  * `graphrag_path_ranking` — all paths between source/target entities
    up to `max_hops` (1..6), ranked by
    `product(edge.confidence) * exp(-0.25 * length)`.
  * `graphrag_neighborhood` — N-hop subgraph from an anchor entity
    with optional edge-type filter (validated against allowlist).
* Cypher templates `graphrag_neighborhood.cypher`,
  `graphrag_path_ranking.cypher` with companion `.json` schemas using
  the new `template_kind: interpolated_depth` mechanism.
* `api/utils/age_template.py` (new): allowlist-based label/edge
  validators (`validate_vertex_label`, `validate_edge_label`),
  `validate_max_hops` with per-call ceiling, `render_path_quantifier`.
* `api/mcp/tools/cypher_query.py`: `_materialise_depth` helper does
  validated integer substitution for path-length quantifiers (which
  AGE openCypher cannot bind as parameters). Refuses missing or
  out-of-range depth values; consumes the parameter so it cannot
  collide with a real binding.
* `api/mcp/skills/registry.py`: registered the new graphrag package
  for skill discovery.

### Phase 3 — AI memory layer (Layer 5)

* Migration `023_memory_layer.sql`: AGE labels for `Session`, `Episode`,
  `ExtractedFact`, `ConceptEntity` (vertices) and `belongs_to`,
  `extracted_from`, `mentions`, `supersedes` (edges). Three relational
  shadow tables — `memory_session_counters`, `memory_extracted_fact_index`,
  `memory_episode_salience` — back the hot-path lookups with O(log n)
  indexes. New SQL helpers: `memory_next_sequence`,
  `memory_recompute_salience`, plus a `memory-salience-recompute` cron
  job at 5-minute intervals.
* `api/config.py`: `SALIENCE_RECENCY_WEIGHT`, `SALIENCE_ACCESS_WEIGHT`,
  `SALIENCE_RELEVANCE_WEIGHT`, `SALIENCE_DECAY` (1-day half-life).
* MCP tools (`api/mcp/tools/`):
  * `memory_remember.py` — `tool_remember(session_id, content,
    source_kind)` allocates the next sequence atomically, MERGEs the
    Session, CREATEs the Episode, runs tier1 NER, and emits MENTIONS
    edges to ConceptEntities. Also exports
    `tool_record_extracted_fact` which detects supersession against
    the relational shadow and writes the SUPERSEDES edge in AGE.
  * `memory_recall.py` — `tool_recall(session_id, query, k=10)` runs
    Phase-1 hybrid_search over-fetched, filters to Episodes in the
    session, and ranks by `0.7 * hybrid + 0.3 * salience`. Bumps
    access_count on returned episodes.
  * `memory_session_start.py` — `tool_session_start(session_id)`
    returns the most-salient recent Episodes, the active
    (non-superseded) ExtractedFacts, and the most-mentioned
    ConceptEntities for the session.
* Two new ADRs: `ADR-0004-salience-formula.md` and
  `ADR-0005-memory-supersession.md`.

### Phase 2 — edge TLP denormalisation

* Migration `022_edge_tlp_denormalization.sql`: every AGE edge label
  table in `core_graph` gets a real `tlp_level smallint NOT NULL`
  column, a CHECK constraint, a btree index, a BEFORE trigger that
  recomputes the value on every write as `GREATEST(properties.tlp_level,
  source.tlp_level, target.tlp_level)`, and a permissive RLS policy
  (`tlp_edge_read_policy`) that filters by the column. IAM edges keep
  their existing RESTRICTIVE TLP:AMBER floor — the new policy is
  AND'd on top, never weakened.
* SECURITY DEFINER helpers `cg_vertex_tlp_level()` and `cg_edge_tlp_sync()`
  encapsulate the cross-table lookup and recompute logic.
* Cascade trigger `cg_vertex_tlp_cascade` (DEFERRABLE INITIALLY DEFERRED)
  on every vertex label table re-fires the per-edge trigger when a
  vertex's `properties.tlp_level` changes, batching the cascade to
  commit time so a single re-classification doesn't re-fire triggers
  mid-transaction.
* `ingest/graph_writer.py`: every `RELATIONSHIP_TEMPLATES` entry now
  sets `e.tlp_level` explicitly using a `CASE WHEN ...` GREATEST
  pattern. The trigger is the safety net, not the sole path.
* `docs/architecture/rls-age-integration.md` updated — the documented
  edge gap is closed.
* `docs/architecture/adr/ADR-0003-edge-tlp-denormalization.md` records
  the rationale, alternatives considered, and operational consequences.

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
