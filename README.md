# core-graph

A converged graph-vector knowledge platform built on PostgreSQL with Apache AGE
and pgvector. Designed for EU-sovereign deployment with security, compliance,
and operational assurance as structural properties.

## What it does

core-graph is a canonical convergence point for heterogeneous data domains:

- **Threat intelligence** (STIX 2.1 native, OpenCTI/MISP integration)
- **Security events** (OCSF-normalised, Wazuh SIEM feed)
- **OSINT** (feed aggregation, entity extraction, deduplication)
- **Standards and legal** (regulatory frameworks, internal documentation, laws)
- **Audit and compliance** (evidence chains, control mapping, NIS2/CRA/GDPR/AI Act)
- **Forensic timelines** (bitemporal facts, chain of custody)

Satellite systems feed structured entities through NATS JetStream into the
PostgreSQL graph-vector core. The platform exposes a Model Context Protocol
(MCP) server for framework-agnostic querying.

## Architecture

**Core:** PostgreSQL 16+ with Apache AGE (openCypher graph), pgvector (HNSW
similarity search), pgAudit (audit logging), and native Row-Level Security.

**Satellites:** Wazuh (SIEM), OpenCTI CE (threat intelligence), MISP (community
sharing), OpenSearch (hot log store), MinIO WORM (evidence store).

**Bus:** NATS JetStream (message broker, subject-based routing per satellite).

**Authorization:** Cerbos (ABAC/TLP) + SpiceDB (ReBAC/compartments) + PostgreSQL
RLS (unforgeable enforcement).

**Evidence integrity:** Append-only audit log with hash chain, MinIO WORM
custody chain, periodic Merkle roots, self-hosted Rekor transparency log.

See [docs/architecture/overview.md](docs/architecture/overview.md) for the full
design.

## Status

**Pre-alpha.** Schema design and architectural documentation phase. Not yet
operational.

## Repository layout

```
core-graph/
├── docs/           Architecture, compliance, ontology, operations
├── schema/         SQL migrations (numbered) and seed data
├── policies/       Authorization policies (Cerbos YAML)
├── ingest/         Satellite connectors, NER pipeline, graph writer
├── api/            MCP server, REST API, GraphQL (optional)
├── deploy/         Docker Compose (dev), Kustomize (lab/prod), NATS config
├── evidence/       Signing, hash chains, Rekor integration
├── tests/          Schema, RLS, ingest, and auth tests
└── scripts/        Bootstrap, validation, seed loading
```

## Conventions

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/)
  with scopes: `feat:`, `fix:`, `docs:`, `schema:`, `policy:`, `deploy:`,
  `test:`, `chore:`
- **Migrations:** Numbered SQL files (`001_`, `002_`, ...). No ORM.
- **Format:** SI units, ISO 8601 dates (YYYY-MM-DD), 24h time, UTC unless
  explicitly local

## Licence

Apache-2.0. See [LICENSE](LICENSE).

The core path (PostgreSQL + AGE + pgvector + NATS + Cerbos + cosign) is
entirely Apache 2.0 / MIT / BSD / PostgreSQL Licence. Satellite components
carry their own licences (GPL, AGPL) and operate as external services, not
embedded in redistributable code.

## Related projects

- [platform-assurance](https://github.com/rmednitzer/platform-assurance) -
  Governance-as-code framework (NIS2/CRA/GDPR/AI Act)
- [cps-assurance](https://github.com/rmednitzer/cps-assurance) -
  Cyber-physical systems assurance
