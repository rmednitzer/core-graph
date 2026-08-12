# Changelog

All notable changes to core-graph are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning of the schema and ontology
contracts. Migrations are forward-only — see `schema/migrations/README.md`.

## Unreleased

### Retrieval model provenance and lifecycle, reconciled against axiom_kg (2026-08)

Records a direct comparison against a running instance of this design
(PostgreSQL 18.4, Apache AGE, pgvector, hybrid retrieval with reranking;
176,235 documents, 51,100 retrieval-active) and adopts three things it does
that this repository did not. Full evidence and the rejected alternatives are
in ADR-0010.

* **schema: add `retrieval_models`** (migration 034) with `kind`
  (`embedding` / `reranker`), `provider`, `repo`, `revision`, nullable `dim`
  and `active`. `embedding_models` recorded only a dimension, could not
  express a reranker at all, and recorded nothing about which weights produced
  a vector — `api/mcp/tools/hybrid_search.py` reranks via `CG_RERANKER_URL`
  with no registry row, so a reranked result set was unattributable. A check
  constraint pairs `dim` with `kind`, so a reranker cannot be used as a vector
  space. Deactivation keeps the row: vectors from a retired model stay
  attributable only while it survives.

  It is a separate table rather than columns on `embedding_models` because
  `make migrate` replays every migration each run, and 021 ends by calling
  `cg_create_model_indexes()` over every non-deprecated row — which raises on
  a null `dim`. A nullable-dim reranker row there would break the *second*
  replay of 021, and 021 re-creates that function, so hardening it later would
  be overwritten.

* **schema: add retrieval lifecycle to `embeddings`** (migration 035):
  `retrieval_active`, `pinned`, `expires_at`, `retention_class`, with a
  constraint that a pinned row cannot carry an expiry. Every row here was
  permanently live, so the vector tier and its HNSW indexes grew without bound.
  Defaults keep every existing row durable and active, so behaviour is
  unchanged until something sets them.

* **schema: add `cg_retrieval_parity`**, reporting active subjects, vectors
  present and the gap per active embedding model. An asymmetry between vector
  spaces makes hybrid fusion search a smaller corpus on one side and shifts the
  blend with no error raised; nothing measured that before.

* **schema: add `pg_trgm`.** `ingest/resolver/` did entity resolution with no
  trigram index available to it.

* **test(schema): `tests/schema/test_retrieval_registry.py`**, exercising every
  new constraint in both directions — a check that is never seen to reject is
  not evidence — plus parity gap detection, reranker exclusion from parity, and
  deactivation preserving the row.

### Backlog completion — STIX SDO set, shared NATS connection, supply-chain gates (2026-06)

Works the carried-forward roadmap of `audit/2026-06-01-engagement.md` § 6 and
the remaining deferred items of ADR-0007.

* **feat(schema,ingest): complete the STIX 2.1 SDO set** (ADR-0007 roadmap #1,
  final part). Migration `033_stix_sdo_completion.sql` creates the
  IntrusionSet / Identity / Location / Report vertex labels with the full
  TLP read+write RLS policy set (028 pattern), SELECT grants at parity with
  the sibling Layer-1 labels (004 pattern), and `stix_id`/`stix_type` indexes
  (030 pattern). The graph writer gains the four MERGE templates (same
  `t_recorded`/`modified`/TLP-ratchet semantics as the existing six); the
  enrichment stage emits the labels instead of deferring them; the OpenCTI
  adapter carries the type-specific fields; TAXII's threat-intel collection
  serves the new types; `stix_lookup` and the label allowlist know them.
  PII minimisation is enforced in the mapping: `identity.contact_information`
  and `location.street_address`/`postal_code` are never stored. STIX's
  optional `location.name` is synthesised from country/region/coordinates.
  Covered by unit tests, `tests/rls/test_stix_sdo_rls.sql`, and a live
  two-stage pipeline integration suite
  (`tests/integration/test_stix_sdo_ingest.py`).
* **perf(api): shared NATS connection for the request paths** (ADR-0007
  deferred #7). `api/nats_client.py` owns one process-wide, lazily-opened,
  loop-aware JetStream connection; `ingest_event` and TAXII add-objects no
  longer pay a connect/close per request, and the INGEST stream is ensured
  once per connection. Closed by the REST lifespan. Unit-pinned by
  `tests/test_nats_client.py`.
* **fix(mcp): the MCP server crashed at import on the current MCP SDK** —
  `FastMCP(description=...)` raises `TypeError` (the SDK parameter is
  `instructions`). Surfaced by the new mypy gate; no test imported
  `api.mcp.server`.
* **fix(authz): SpiceDB `delete_relationship` built an invalid protobuf** —
  `optional_subject_filter` was a `SubjectReference`; the field is a
  `SubjectFilter`, so every call raised `TypeError` (the SpiceDB twin of the
  A-01 Cerbos wire bug, in the ADR-0008 deferred scaffolding). Also surfaced
  by mypy.
* **build(deps): committed `uv.lock`** (ADR-0009 / SC-03 / ADR-0007 #5) —
  sha256-pinned universal resolution, enforced in CI by a networked
  `uv lock --check` job; Renovate's existing `lockFileMaintenance` keeps it
  current.
* **ci: mypy type gate** (audit § 6.3) — permissive `[tool.mypy]` config over
  `api`/`ingest`/`evidence`; the tree was made mypy-clean in this change (9
  findings fixed, two of them runtime bugs above), so the job is blocking
  from the start.
* **ci: unit-coverage floor** (audit § 6.4) — `pytest-cov` with
  `--cov-fail-under=48` (soft ratchet two points under the measured 50%
  baseline) plus a coverage.xml artifact.
* **ci: license-policy gate** (audit § 6.5) — `scripts/license_gate.py` scans
  the runtime closure (deny GPL/AGPL/SSPL; LGPL allowed — psycopg), publishes
  `license-report.json`, and an SPDX SBOM rendition is produced next to the
  CycloneDX one. NOTICE corrected: the psycopg family is LGPL-3.0-only, not
  permissive.
* **test(integration): `label(v) = $label` execution test** (C-02, deferred
  twice for want of a live AGE) — `tests/integration/test_cypher_templates.py`
  executes `count_entities_by_label` and `get_entity_by_label_and_value`
  against the populated graph, both directions (match and filter-out).
* **fix(evidence): `verify_locked` treats a missing retention config as
  unlocked** instead of relying on an `AttributeError` falling into the
  broad exception handler.

### Authorization role-vocabulary reconciliation (A-03, 2026-06)

* **fix(authz): key the application-layer role guards on the bare JWT roles.**
  Follow-up to the Phase 8 A-03 finding. `api/utils/age_query_guard.py` keyed its
  per-role depth (`ROLE_MAX_DEPTH`) and timeout (`ROLE_TIMEOUT_MS`) tables on the
  `cg_`-prefixed **database-role** spelling, but `api/db.py` feeds them the
  **application** roles from `caller_identity["roles"]` (the bare names the OIDC
  IdP emits). Every caller therefore silently fell back to `DEFAULT_MAX_DEPTH` /
  `DEFAULT_TIMEOUT_MS` — e.g. a `ciso` got the 30 s default instead of 120 s. The
  tables are now keyed on the bare names; `tests/test_age_query_guard.py` is
  rewritten to assert the bare vocabulary (the old test had locked in the
  `cg_` spelling) and adds regression guards that the keys are never
  `cg_`-prefixed and that a `cg_ciso` string resolves to the defaults.
* **Two role namespaces documented.** The `cg_`-prefixed names are PostgreSQL
  **database roles** (created in the migrations, targeted by the RLS `GRANT`s);
  the bare names are the **application** roles (JWT claim → Cerbos +
  `age_query_guard`). The dormant `schema/seed/roles.sql` clearances and the
  application-role references in the docstrings, CLAUDE.md, and the architecture
  docs are aligned to the bare names; the database roles in the migrations are
  intentionally left `cg_`-prefixed. `docs/architecture/authorization-model.md`
  gains a note spelling out the distinction, and ADR-0008 decision 5 is updated.
  Also corrects the depth table's stale `ciso = unlimited` to the actual `10`.

### Phase 8 — authorization & resilience audit (2026-06)

* New ADR
  `docs/architecture/adr/ADR-0008-authorization-layering.md` records the
  authorization-layering decision the 2026-05-27 assurance engagement
  recommended but had not yet been written: **RLS is the primary, unforgeable
  boundary; Cerbos (ABAC) gates the high-assurance identity-attribution write;
  SpiceDB (ReBAC) is retained as scaffolding with explicit activation
  criteria.** Resolves the long-open S-01 (Cerbos unused), S-02 (SpiceDB
  unused), and M-01 (two Cerbos client implementations) findings.
* **fix(authz): corrected the Cerbos `/api/check/resources` wire format and
  consolidated onto one client.** The audit found both Cerbos clients were
  wire-incorrect against the documented Cerbos API (verified against the v0.53
  reference), in different ways: the canonical `api/authz/cerbos.py` posted the
  singular `resource` + top-level `actions` shape to the plural endpoint, while
  the *only wired* call — the CISO-gated identity-attribution path — read the
  per-action effect as `actions[action].effect`. Cerbos returns each effect as
  a **string** (`"EFFECT_ALLOW"`/`"EFFECT_DENY"`), so `.get("effect")` raised
  `AttributeError` and fail-closed **every** decision: identity attribution
  denied all requests against a live Cerbos and the breakage was invisible (no
  live-Cerbos test exercised the parse). `api/authz/cerbos.py` now exposes a
  single correct `check_action()` (batch request, string-effect parse,
  fail-closed); `check_resource()` delegates to it; and
  `api/mcp/tools/identity_attribution.py` drops its bespoke inline client and
  delegates too — giving the canonical client its first real caller. Pinned by
  the new `tests/test_cerbos_client.py` (9 cases: allow/deny, the
  string-not-object regression, the batch request shape, empty-result and
  transport-error fail-closed, and the `CallerIdentity` principal mapping).
* **Cerbos role vocabulary clarified (a PR-review finding).** Codex flagged a
  potential role mismatch on the Cerbos gate. Confirmed with the maintainer that
  the OIDC IdP emits **bare** role names (`ciso`, …), so `derived_roles.yaml` and
  the `tests/auth` fixtures are correct as-is (bare `parentRoles`) — with the
  wire-format fix above, a real `ciso` caller is now correctly allowed. A
  divergence is recorded for follow-up: `schema/seed/roles.sql`, the RLS
  policies, `api/utils/age_query_guard.py`, the docstrings, and CLAUDE.md use
  `cg_`-prefixed names for the same hierarchy, so `age_query_guard`'s
  role→depth/timeout lookups silently fall back to defaults under the bare
  vocabulary. Reconciling those `cg_` sites to the bare names touches
  seed/reference data and CLAUDE.md and is left to a dedicated PR (ADR-0008
  decision 5; A-03 in the engagement record).
* **fix(dlq): reconnect the DLQ processor's PostgreSQL connection on
  `OperationalError` (R-02).** The processor holds one long-lived connection;
  if it dropped (server restart, failover, idle timeout) every subsequent
  delivery failed against the dead handle and the queue silently stopped
  draining. `ingest/dlq/processor.py` now reconnects on
  `psycopg.OperationalError` (and re-checks `conn.closed` before each message),
  NAK-ing the in-flight delivery so JetStream redelivers it against the fresh
  connection; non-connection errors still roll back and NAK without a spurious
  reconnect. Covered by `tests/test_dlq_reconnect.py`.
* **NOTICE file** added (Apache-2.0 attribution, P1-07): states the project
  copyright and ties the authoritative third-party component/license inventory
  to the CycloneDX SBOMs already produced by `security.yml` / `release.yml`,
  and records the satellite-systems-are-external-services posture.
* `SECURITY.md` authorization section updated to match the corrected runtime
  (single Cerbos client; SpiceDB deferral now a recorded decision, not "pending
  integration") and to reference ADR-0008.
* Engagement record `audit/2026-06-01-engagement.md` documents the full gap
  inventory, dispositions, and the carried-forward roadmap.

### Phase 7 — modernization audit (2026-05)

* New ADR
  `docs/architecture/adr/ADR-0007-modernization-audit-2026-05.md` records a
  full-repository modernization pass validated against primary sources
  (PostgreSQL 18 release notes, Apache AGE releases, the pgvector changelog,
  the MCP Python SDK, Sigstore) with a prioritised roadmap for deferred
  items.
* **Engine currency.** PostgreSQL 16 → 18 and Apache AGE 1.6.0 → 1.7.0 across
  the `setup-pg-age` CI action, `Dockerfile.postgres`, the Helm values, the
  Zarf package, and all docs. pgvector 0.8.0 → 0.8.2 — the first 0.8.x line
  with PostgreSQL 18 support (0.8.0 does not compile against the PG18 server
  headers) — with the tarball SHA-256 pinned in both build paths.
* **Migration 027** (`027_pgvector_iterative_scan.sql`) enables pgvector 0.8
  HNSW iterative index scans (`strict_order`) at the database level, fixing
  RLS "overfiltering" where a TLP- or compartment-filtered vector query could
  silently return fewer than the requested `LIMIT`.
* **Toolchain.** Python aligned on 3.13 throughout (the runtime image already
  shipped 3.13 but CI and the `requires-python` floor were still 3.12):
  `requires-python >=3.13`, ruff `target-version = py313`, and
  `python-version: "3.13"` across the test/lint/eval workflows.
* **Ingest enrichment stage.** New `ingest/enrichment.py` +
  `ingest/enrichment_worker.py` consume the raw `ingest.*` messages published
  by the feed-style connectors (OpenCTI, MISP, OSINT, Wazuh), run the
  NER/resolution stage, and republish graph-writable `enriched.entity.*` /
  `enriched.relationship.*` envelopes. Previously those four connectors
  published to `ingest.*` with no consumer, so their data never reached the
  graph. Covered by `tests/ingest/test_enrichment.py`.
* **Supply chain.** New `.github/workflows/release.yml` builds, generates SLSA
  build provenance, and signs the container images with cosign (keyless OIDC)
  on tagged releases.
* **Deployment hygiene.** Removed the duplicate Kustomize tree
  (`deploy/k8s/base/` and `overlays/`, since ArgoCD, CI, and Zarf all consume
  the Helm chart) and the empty `api/graphql/` placeholder. Added CPU/memory
  `limits` for the NATS, Valkey, and graph-writer workloads, and a readiness
  probe for the graph-writer, which now drops a `/tmp/graph-writer.ready`
  marker once its JetStream subscription is live.
* **Edge-level RLS made effective against the Cypher write path.** Apache AGE
  1.7 executes Cypher through its own executor and does **not** fire the
  per-table triggers, so the migration-022 `trg_edge_tlp_sync` /
  `trg_vertex_tlp_cascade` triggers never ran for graph writes (every
  production write goes through `ag_catalog.cypher()`). The denormalized edge
  `tlp_level` column that `tlp_edge_read_policy` filters on was therefore left
  at its `0` default, so edge-level RLS admitted Cypher-created edges to every
  caller regardless of marking. Every Cypher edge-write path now maintains the
  column with explicit SQL via the shared `api/utils/edge_tlp.py` helpers
  (`sync_edges_tlp` for known edge ids, `resync_vertex_edges` for an endpoint):
  `ingest/graph_writer.py` (all six relationship templates, draining every
  returned row so a multi-edge MERGE is fully synced, plus a vertex-MERGE
  cascade), `api/mcp/tools/identity_attribution.py` (the CISO-gated
  `same_as` edge), and `api/mcp/tools/memory_remember.py`
  (`mentions` / `extracted_from` / `supersedes`). **Migration 032**
  (`032_edge_tlp_writer_resync.sql`) adds the callable `cg_resync_vertex_edges`
  cascade helper (pinned `search_path`, `EXECUTE` revoked from `PUBLIC`) and
  re-backfills `tlp_level` on existing edges. No RLS policy is changed: the fix
  only makes the column the policy reads truthful. Covered by new writer and
  memory integration tests and the rewritten `tests/rls/test_edge_tlp.sql`,
  now wired into the `schema-and-rls-test` CI job (previously it ran only under
  `make test` and had silently broken).

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
