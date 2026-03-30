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
- Row-Level Security enforces TLP markings at the engine level.
- Cerbos (ABAC) + SpiceDB (ReBAC) for authorization decisions.
- Bitemporal modeling: four timestamps per fact (t_valid, t_invalid,
  t_recorded, t_superseded). Facts invalidated, never deleted.
- Evidence integrity via append-only audit log + MinIO WORM + cosign + Rekor.
- MCP server is the primary AI agent interface.
- Eight ontology layers: threat intel, security events, OSINT, audit/compliance,
  AI memory, forensic timeline, infrastructure & assets, identity & access
  management.
- STIX 2.1 as canonical threat intelligence data model.
- OCSF as event normalisation layer.
- Connection pooling via psycopg-pool (not per-request connections).
- SpiceDB for ReBAC (Zanzibar model).
- Cerbos for ABAC (YAML policies in `policies/`).
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

## Coding conventions

- Python 3.12+, type hints required, ruff for linting
- SQL migrations are numbered files (001_, 002_, ...). No ORM.
- Conventional commits: feat:, fix:, docs:, schema:, policy:, deploy:, test:, skill:
- Smallest safe increments. Reversible-first.
- No speculative features. Build what is needed now.
- SI units, ISO 8601 dates, 24h time, UTC unless explicitly local

## Security constraints

- Never commit secrets, keys, or credentials
- Never weaken RLS policies without explicit justification
- Never bypass authorization (Cerbos/SpiceDB) at the application layer
- All SQL must use parameterised queries (CVE-2022-45786 mitigation)
- Cypher queries through AGE must use query templates, not string concatenation

## File organisation

- `schema/migrations/` - Database schema (numbered SQL, idempotent)
- `schema/seed/` - Reference data (MITRE ATT&CK, STIX vocabularies, roles)
- `policies/` - Cerbos YAML policies (first-class, not config)
- `ingest/` - Satellite connectors, NER pipeline, entity resolution, graph writer
- `api/` - MCP server, REST API (FastAPI), optional GraphQL
- `deploy/` - Docker Compose (dev), Kustomize (lab/prod), NATS config
- `evidence/` - cosign signing, hash chain computation, Rekor config
- `tests/` - Schema validation, RLS enforcement, ingest integration, auth decisions
- `api/authz/` - SpiceDB and Cerbos client modules
- `api/mcp/skills/` - Skill registry, base class, query templates, skill implementations
- `api/db.py` - Shared connection pool
- `ingest/connectors/base.py` - Shared adapter base class
- `ingest/dlq/` - Dead-letter queue processor
- `docs/` - Architecture, compliance mapping, ontology design, operations

## What not to do

- Do not add Neo4j, ArangoDB, or any alternative graph database
- Do not replace NATS with Kafka or RabbitMQ
- Do not use an ORM for schema management
- Do not embed satellite system code (Wazuh rules, OpenCTI connectors) directly;
  use the ingest adapter pattern
- Do not store PII in the graph without pseudonymisation
- Do not create API endpoints that bypass Cerbos policy evaluation
