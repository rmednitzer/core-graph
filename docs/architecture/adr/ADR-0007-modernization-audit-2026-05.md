# ADR-0007: Modernization audit and engine upgrade (2026-05)

## Status

Accepted (recorded 2026-05-31). Builds on ADR-0006 (code-base validation).

## Context

ADR-0006 validated the code against upstream documentation as it stood in
2026-05-24 but explicitly "did not drive new feature work". This pass is the
follow-up that does: a modernization audit whose remit was to bring the
architecture up to current upstream releases, remove redundant parts, and
close the highest-value gaps — while keeping the platform's structural
properties (RLS/TLP enforcement, bitemporal facts, evidence integrity)
intact.

### Method

Four independent read-only survey passes covered the database/schema layer,
the API layer, the ingest pipeline, and deployment/CI/tooling. Each finding
was then re-verified against the code directly (several agent findings were
discarded as false positives — e.g. GitHub Action version ordering, the
`Bearer` header parse, and CORS credentialed-request claims were all
already correct). Version currency was checked against primary upstream
sources rather than search summaries.

### Trusted sources consulted

- PostgreSQL 18 — GA 2025-09-25. Release notes confirm native temporal
  constraints (`WITHOUT OVERLAPS` / `PERIOD`), `uuidv7()`, virtual generated
  columns, `RETURNING OLD/NEW`, and asynchronous I/O.
  <https://www.postgresql.org/docs/release/18.0/>
- Apache AGE — `release_PG18_1.7.0` is the current release and is published
  for PostgreSQL 18 (and 17). AGE is no longer the version ceiling it
  historically was. <https://github.com/apache/age/releases>
- pgvector 0.8.0 — adds `halfvec`/`sparsevec` and HNSW/IVFFlat **iterative
  index scans** for filtered search.
  <https://www.postgresql.org/about/news/pgvector-080-released-2952/>
- MCP Python SDK (`mcp`) — current line is 1.x (1.27+).
  <https://github.com/modelcontextprotocol/python-sdk>
- Sigstore cosign + Rekor and SLSA build provenance via
  `actions/attest-build-provenance` — used for the release signing workflow.

## Decision

Upgrade the canonical engine and toolchain to current releases, consolidate
duplicated deployment artifacts, add supply-chain signing, and build the
missing ingest enrichment stage. Defer changes that cannot be validated in
the current environment (no live Postgres/AGE/NATS stack; PyPI egress is
restricted) to a tracked roadmap rather than shipping them untested.

## Implemented in this pass

### Engine and toolchain currency

| Component | Was | Now | Source of "now" |
|---|---|---|---|
| PostgreSQL | 16 | 18 | PG18 GA 2025-09-25 |
| Apache AGE | 1.6.0 (PG16) | 1.7.0 (PG18) | apache/age releases |
| pgvector | 0.8.0 | 0.8.0 + iterative scans enabled | pgvector 0.8 notes |
| Python (runtime + CI + floor) | 3.13 runtime / 3.12 CI & floor | 3.13 throughout | — |

- The PG16→18 / AGE1.6→1.7 bump spans the `setup-pg-age` CI action,
  `Dockerfile.postgres`, Helm values, the Zarf package, and all docs. CI's
  `schema-and-rls-test` job replays all 27 migrations and the RLS suite
  against PG18/AGE1.7 on every PR, so the upgrade is exercised end-to-end.
- Migration `027_pgvector_iterative_scan.sql` enables HNSW `iterative_scan`
  (`strict_order`) at the database level. This specifically fixes RLS
  **overfiltering**: because TLP/compartment predicates apply after the index
  returns candidates, a plain HNSW scan could silently return fewer than the
  requested `LIMIT`. The migration is defensively guarded so an older
  pgvector build cannot break the migration chain.
- The Python runtime/CI/`requires-python`/ruff target are aligned on 3.13,
  removing the prior test-on-3.12 / ship-on-3.13 skew.

### Pruned / consolidated

- Removed the duplicate Kustomize `deploy/k8s/base` + `overlays` tree. ArgoCD,
  Zarf, the Makefile, and CI all template via Helm only; nothing referenced
  Kustomize.
- Removed the empty `api/graphql/` placeholder.
- Added CPU/memory limits to nats/valkey/graph-writer and a real
  readiness probe to the graph-writer (marker file written once its
  subscription is live).

### Supply chain

- Added a release-gated workflow that builds and pushes the app and postgres
  images by digest, signs them with cosign keyless (Sigstore Fulcio + Rekor),
  and attests SLSA build provenance — reusing the cosign + Rekor primitives
  already in the evidence architecture. `security.yml` keeps the verify half
  (Trivy/SBOM/secret scanning) on every PR.

### Ingest correctness (the largest gap)

The "NER + Entity Resolution" stage in the architecture diagram was never
built. opencti, misp, osint, and wazuh published source-shaped messages to
`ingest.*`, but the graph writer consumes only `enriched.>` and nothing
subscribed to `ingest.*` — so four of eight connectors' data never reached
the graph (and ingest_event/TAXII were silently in the same state).

- Added `ingest/enrichment.py` (pure, unit-tested mappers) and
  `ingest/enrichment_worker.py` (the consumer). It normalises OSINT IOCs,
  Wazuh OCSF events, MISP/OpenCTI envelopes, raw TAXII STIX objects, and
  API-ingested OCSF into the canonical `{label, properties}` envelopes the
  writer MERGEs. STIX `object_marking_refs` are honoured so partner TLP
  markings are never under-classified.
- Consolidated the four bespoke per-source streams onto one shared `INGEST`
  work-queue stream and wired the worker into Helm (Deployment + NATS-egress
  NetworkPolicy + limits + readiness probe) and the Makefile.
- **Only labels backed by a real MERGE template are emitted**; a unit test
  enforces `WRITABLE_ENTITY_LABELS ⊆ MERGE_TEMPLATES`.

### API hardening

- `readyz` no longer blocks the event loop on the synchronous MinIO client
  (`asyncio.to_thread`); the NATS/Valkey readiness checks gained timeouts.
- ingest_event and the TAXII add-objects path gained NATS connect/publish
  timeouts.

## Deferred — roadmap

These are real findings from the survey that were **not** shipped here,
because they either require a live stack to validate (and "validate
everything" forbids shipping them blind) or are large enough to warrant
their own change. Ordered by value.

1. **STIX SDO MERGE templates.** The graph writer has no template for
   ThreatActor / Malware / Campaign / AttackPattern / Vulnerability / Tool /
   IntrusionSet / Identity / Location / Report. The enrichment stage therefore
   *defers* these (reports them, never emits droppable vertices). Adding the
   templates is the natural completion of the threat-intel layer but needs
   AGE-live validation of each Cypher MERGE.
2. **PG18 native temporal constraints.** Replace the trigger/exclusion-based
   bitemporal invariants (migrations 020/026) with native `WITHOUT OVERLAPS`
   primary keys once the `valid_range` modelling is reworked to a range
   column. Requires a live PG18 to validate constraint semantics and a data
   backfill plan.
3. **RLS write-path policies.** Vertex/edge tables have `SELECT` RLS only;
   writes are gated by the graph-writer service role + Cerbos. Add
   `INSERT/UPDATE/DELETE` RLS for defense-in-depth, with matching
   `tests/rls/` cases (RLS changes must ship with a passing SQL test).
4. **graph_writer replay idempotency.** At-least-once redelivery re-runs the
   audit-log insert and temporal-fact insert (the vertex MERGE is already
   idempotent). Add a delivery-id dedup key. Needs the live stack to test
   redelivery.
5. **Dependency lockfile.** The repo deliberately uses loose floors managed
   by a sophisticated `dependabot.yml`; a `uv.lock` should be generated and
   enforced (`uv lock --check`) in a networked CI step — it cannot be
   produced in this sandbox (PyPI egress blocked).
6. **Third-party action SHA-pinning.** `trufflehog@main` and
   `trivy-action@master` should be pinned to release SHAs. Dependabot already
   surfaces their tagged releases; SHA resolution needs network access.
7. **NATS connection pooling** for ingest_event/TAXII (currently one
   connection per request) and **multi-arch image builds**.

## Validation performed

- `ruff check` + `ruff format --check`: clean across the tree (py313 target).
- `scripts/validate.py`: migration numbering 001–027, policy YAML, secrets.
- `helm lint` + `helm template` (lab + prod) render the new enrichment-worker
  Deployment, its NetworkPolicy, and the added resource limits.
- The `ingest.enrichment` mapping logic was exercised directly (the
  pure-function assertions in `tests/ingest/test_enrichment.py`); the two
  graph_writer-dependent assertions run in CI where the deps are installed.
- The engine upgrade and any new SQL are validated by CI's migration-replay
  and integration jobs against PG18/AGE1.7.
