# CLAUDE.md

Instructions for AI assistants working on this repository.

## Project identity

core-graph is a converged graph-vector knowledge platform. PostgreSQL with
Apache AGE (graph) and pgvector (embeddings) is the canonical store. Satellite
systems (Wazuh, OpenCTI, MISP, OpenSearch, MinIO, Netbox, Prometheus) feed
structured entities through NATS JetStream into the core.

Target: EU-sovereign, single-engineer operable, auditable, evidence-producing.

## Architecture decisions (do not contradict)

- PostgreSQL is the core. Not Neo4j, not ArangoDB. Decision is final.
- Apache AGE for graph (openCypher). GQL trajectory.
- pgvector for embeddings (HNSW). Not Qdrant (that stays in ai-stack).
- NATS JetStream as message bus. Not Kafka, not RabbitMQ.
- Valkey for cache and rate-limit state (the Python `redis` client speaks to
  Valkey; do not introduce Redis Inc. server distributions).
- Row-Level Security enforces TLP markings at the engine level.
- Cerbos (ABAC) + SpiceDB (ReBAC) for authorization decisions.
- Bitemporal modeling: four timestamps per fact (t_valid, t_invalid,
  t_recorded, t_superseded). Facts invalidated, never deleted.
- Evidence integrity via append-only audit log + MinIO WORM + cosign + Rekor.
  Merkle roots are stamped via RFC 3161 (`scripts/stamp_merkle_roots.py`).
- MCP server is the primary AI agent interface.
- Eight ontology layers: threat intel, security events, OSINT, audit/compliance,
  AI memory, forensic timeline, infrastructure & assets, identity & access
  management.
- STIX 2.1 as canonical threat intelligence data model.
- OCSF as event normalisation layer.
- TAXII 2.1 endpoint exposes threat intel to authorised clients.
- Connection pooling via psycopg-pool (not per-request connections).
- OIDC for authentication (pluggable IdP).
- Dead-letter queue with retry and archive.
- Skills live in `api/mcp/skills/`. Each skill implements `SkillBase`. New
  capabilities are added as skills, not as raw Cypher templates.
- Cross-domain Cypher templates live in `api/mcp/skills/queries/` as `.cypher`
  files with companion `.json` parameter schemas.
- IAM data (Layer 8) has a TLP:AMBER floor enforced at the RLS layer. No IAM
  vertex is ever visible below TLP:AMBER.
- `Principal--same_as--ThreatActor` edges require explicit `cg_ciso`
  authorization via `tool_assert_identity_attribution`. Never created
  automatically.
- Adapter base class is `ingest/connectors/base.py`. New adapters must extend
  `AdapterBase`.
- Embedding provider is configured via `CG_EMBEDDING_PROVIDER`. Default is
  `none`.

## Quick reference (Make targets)

Run `make help` for the full list. Most-used targets:

- `make up` / `make down` / `make reset` — Docker dev stack lifecycle
- `make migrate` / `make seed` — Apply schema migrations and seed data
- `make serve` / `make mcp` / `make graph-writer` — Run a service locally
- `make psql` — Open a psql shell against the dev database
- `make test` — pytest + RLS SQL suites
- `make integration-test` — End-to-end suites (require running Docker stack)
- `make lint` / `make validate` — ruff check + ruff format + yamllint +
  migration numbering check
- `make verify-chain` / `make verify-merkle` / `make stamp-merkle` — Audit
  log integrity operations
- `make bench` / `make eval` / `make drift` — Benchmarks, retrieval eval,
  embedding drift detector
- `make helm-lint` / `make helm-template` / `make zarf-validate` /
  `make deploy-lint` — Deployment artifact validation

## Configuration

All runtime configuration uses the `CG_` prefix and is read in `api/config.py`.
Service code must import from `api.config`; do not call `os.environ` directly.
New variables are added to `api/config.py` with a sensible default.

Key groups (see `api/config.py` for the complete list):

- Database / pool: `CG_PG_DSN`, `CG_PG_POOL_MIN`, `CG_PG_POOL_MAX`
- Bus / cache: `CG_NATS_URL`, `CG_VALKEY_URL`
- Authz: `CG_SPICEDB_ENDPOINT`, `CG_SPICEDB_TOKEN`, `CG_CERBOS_ENDPOINT`
- Auth: `CG_OIDC_ENABLED`, `CG_OIDC_ISSUER_URL`, `CG_OIDC_AUDIENCE`,
  `CG_OIDC_JWKS_CACHE_TTL`
- Evidence: `CG_MINIO_*`, `CG_TSA_URL`, `CG_TSA_ENABLED`
- Embedding: `CG_EMBEDDING_PROVIDER`, `CG_EMBEDDING_MODEL`,
  `CG_EMBEDDING_URL`, `CG_EMBEDDING_DIMENSIONS`
- Memory salience: `CG_SALIENCE_RECENCY_WEIGHT`, `CG_SALIENCE_ACCESS_WEIGHT`,
  `CG_SALIENCE_RELEVANCE_WEIGHT`, `CG_SALIENCE_DECAY`
- Operational defaults: `CG_DEFAULT_TLP`, `CG_CORS_ORIGINS`,
  `CG_PROMETHEUS_WEBHOOK_HOST`, `CG_PROMETHEUS_WEBHOOK_PORT`

## Coding conventions

- Python 3.12+, type hints required, ruff for linting (`line-length = 100`,
  `target-version = "py312"`)
- Ruff `select = ["E", "F", "I", "W", "UP", "B", "S"]`. Do not silence
  S-rules outside the per-file-ignores already declared in `pyproject.toml`
- SQL migrations are numbered files (`001_`, `002_`, ...). No ORM. Idempotent
  (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`). Add the next sequential number;
  never renumber or amend a committed migration — write a new one
- pytest is configured with `asyncio_mode = "strict"` and `--strict-markers`.
  Adding a new marker means updating `[tool.pytest.ini_options].markers` in
  `pyproject.toml`
- Conventional commits with project scopes: `feat:`, `fix:`, `docs:`,
  `schema:`, `policy:`, `deploy:`, `test:`, `skill:`
- Smallest safe increments. Reversible-first.
- No speculative features. Build what is needed now.
- SI units, ISO 8601 dates, 24h time, UTC unless explicitly local

## Testing

Test layout (`tests/`):

- `tests/auth/` — Cerbos policy decision tests (YAML)
- `tests/rls/` — Row-Level Security enforcement (SQL, executed by `make test`)
- `tests/schema/` — Migration numbering and validity
- `tests/ingest/` — Connector adapters, NER, entity resolution
- `tests/skills/` — MCP skill registry and individual skills
- `tests/taxii/` — TAXII 2.1 endpoint compliance
- `tests/eval/` — Retrieval evaluation against the golden set
- `tests/integration/` — End-to-end flows; mark with
  `@pytest.mark.integration` and run via `make integration-test`

Schema, RLS, or policy changes require a corresponding test in the matching
subdirectory. For a single file: `pytest tests/<subdir>/test_<name>.py -v`.

## Security constraints

- Never commit secrets, keys, or credentials
- Never weaken RLS policies without explicit justification, accompanied by a
  passing `tests/rls/` change demonstrating the new behaviour
- Never bypass authorization (Cerbos/SpiceDB) at the application layer
- All SQL must use parameterised queries (CVE-2022-45786 mitigation)
- Cypher queries through AGE must use templates from
  `api/mcp/skills/queries/`, not string concatenation
- AGE Cypher parameters use `$name` syntax bound via agtype JSON; this requires
  PREPARE/EXECUTE or PL/pgSQL EXECUTE. Labels and relationship types cannot
  be parameterized and must pass `validate_label()` before interpolation
- Audit log rows are append-only; never UPDATE or DELETE past entries
- Do not store PII in the graph without pseudonymisation
- Do not create API endpoints that bypass Cerbos policy evaluation

## File organisation

- `schema/migrations/` — Numbered SQL migrations (idempotent)
- `schema/seed/` — Reference data (MITRE ATT&CK, STIX vocabularies, roles)
- `policies/` — Cerbos YAML policies
  - `policies/derived_roles.yaml`
  - `policies/resource/` — One file per resource kind
  - `policies/principal_policies/`
- `ingest/` — Satellite connectors and writer
  - `ingest/connectors/base.py` — `AdapterBase` (extend for new connectors)
  - `ingest/connectors/{keycloak,misp,netbox,opencti,osint,prometheus,wazuh}/`
  - `ingest/dlq/` — Dead-letter queue processor
  - `ingest/ner/`, `ingest/resolver/` — NER and entity resolution
  - `ingest/graph_writer.py` — NATS JetStream → PostgreSQL writer
- `api/` — Service code
  - `api/config.py` — All `CG_*` env var bindings
  - `api/db.py` — Shared psycopg-pool connection pool
  - `api/authz/` — Cerbos and SpiceDB clients
  - `api/mcp/` — MCP server
    - `api/mcp/server.py`
    - `api/mcp/skills/base.py` — `SkillBase` abstract class
    - `api/mcp/skills/registry.py` — Skill discovery
    - `api/mcp/skills/queries/` — Cypher templates + JSON parameter schemas
    - `api/mcp/skills/{asset,threat,compliance,graphrag,identity}/` — Skills
    - `api/mcp/tools/` — Direct tools (cypher_query, identity_attribution, …)
  - `api/rest/` — FastAPI app, middleware, routes
  - `api/taxii/` — TAXII 2.1 endpoint
  - `api/graphql/` — Optional GraphQL interface
- `deploy/` — `docker/` (Compose), `k8s/` (Kustomize base+overlays, Helm
  chart, ArgoCD apps), `nats/`, `grafana/`
- `evidence/` — cosign signing, hash-chain computation, Rekor config
- `scripts/` — bootstrap, MinIO init, migration validation, Merkle stamping;
  `scripts/bench/` (perf), `scripts/eval/` (retrieval evaluation)
- `tests/` — See "Testing" above
- `docs/` — `architecture/adr/`, `ontology/`, `operations/runbooks/`

## Common recipes

**Add a skill.** Create a module under `api/mcp/skills/<domain>/`, subclass
`SkillBase` from `api/mcp/skills/base.py`, and ensure it is picked up by the
discovery in `api/mcp/skills/registry.py`. If the skill needs cross-domain
graph access, add the Cypher to `api/mcp/skills/queries/<name>.cypher` with a
matching `<name>.json` parameter schema. Add a test under `tests/skills/`.

**Add a connector.** Subclass `AdapterBase` in
`ingest/connectors/<source>/`, wire it into the dispatch used by
`ingest/graph_writer.py`, and add a test under `tests/ingest/`.

**Add a migration.** Create `schema/migrations/NNN_<name>.sql` with the next
sequential number. Make it idempotent. Run `make validate` to confirm
numbering, then `make migrate` against the dev database. If the migration
changes RLS or temporal invariants, add or update the matching test.

**Add a Cerbos policy.** Add a YAML file under `policies/resource/` (or extend
`policies/derived_roles.yaml`). Add a corresponding decision test under
`tests/auth/`. Run `make validate` to lint the YAML.

**Add a config flag.** Bind it in `api/config.py` with a sensible default.
Reference via `from api import config`, never via `os.environ` in service
code. Document the new variable in the relevant section of `docs/`.

## What not to do

- Do not add Neo4j, ArangoDB, or any alternative graph database
- Do not replace NATS with Kafka or RabbitMQ
- Do not swap Valkey for Redis Inc. server distributions
- Do not use an ORM for schema management
- Do not embed satellite system code (Wazuh rules, OpenCTI connectors)
  directly; use the ingest adapter pattern
- Do not store PII in the graph without pseudonymisation
- Do not create API endpoints that bypass Cerbos policy evaluation
- Do not amend, renumber, or delete a committed migration; write a new one
- Do not bypass `SkillBase` by adding ad-hoc query handlers to the MCP server
- Do not introduce per-request database connections; use the pool in
  `api/db.py`
- Do not call `os.environ` from service code; route all config through
  `api/config.py`
- Do not create `Principal--same_as--ThreatActor` edges from automated flows;
  they require `cg_ciso` via `tool_assert_identity_attribution`
- Do not add a pytest marker without registering it in `pyproject.toml`
