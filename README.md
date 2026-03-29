# Core-Graph

A converged graph-vector knowledge platform built on PostgreSQL with Apache AGE
and pgvector. Designed for EU-sovereign deployment with security, compliance,
and operational assurance as structural properties.​

<!-- Badges placeholder -->
<!-- ![CI](https://github.com/rmednitzer/core-graph/actions/workflows/test.yml/badge.svg) -->
<!-- ![License](https://img.shields.io/badge/license-Apache--2.0-blue) -->

## What it does

core-graph is a canonical convergence point for heterogeneous data domains:

- **Threat intelligence** (STIX 2.1 native, OpenCTI/MISP integration)
- **Security events** (OCSF-normalised, Wazuh SIEM feed)
- **OSINT** (feed aggregation, entity extraction, deduplication)
- **Standards and legal** (regulatory frameworks, internal documentation, laws)
- **Audit and compliance** (evidence chains, control mapping, NIS2/CRA/GDPR/AI Act)
- **Forensic timelines** (bitemporal facts, chain of custody)

## Status

**Alpha:** local development stack operational, schema stable, ingest pipeline
functional.

## Quick start

```bash
git clone https://github.com/rmednitzer/core-graph.git
cd core-graph
./scripts/bootstrap.sh
make serve    # REST API on :8000
make mcp      # MCP server
```

## Architecture

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Wazuh     │   │  OpenCTI    │   │    MISP     │
│   (SIEM)    │   │  (ThreatI.) │   │  (Sharing)  │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       └────────┬────────┴────────┬────────┘
                │  NATS JetStream │
                └────────┬────────┘
                         │
           ┌─────────────┴─────────────┐
           │     PostgreSQL 16+        │
           │  ┌───────┐  ┌──────────┐  │
           │  │  AGE   │  │ pgvector │  │
           │  │(graph) │  │ (embed.) │  │
           │  └───────┘  └──────────┘  │
           │  RLS · pgAudit · pg_cron  │
           └─────────────┬─────────────┘
                         │
              ┌──────────┴──────────┐
              │    REST + MCP API   │
              │  Cerbos · SpiceDB   │
              └─────────────────────┘
```

## Development

| Target              | Description                              |
|---------------------|------------------------------------------|
| `make up`           | Start Docker Compose dev stack           |
| `make down`         | Stop dev stack                           |
| `make migrate`      | Run database migrations                  |
| `make seed`         | Load reference data                      |
| `make serve`        | REST API on :8000 (uvicorn --reload)     |
| `make mcp`          | Run MCP server                           |
| `make graph-writer` | Run graph writer worker                  |
| `make test`         | Run all tests                            |
| `make lint`         | Lint Python and YAML                     |
| `make verify-chain` | Verify audit log hash chain              |

## Repository layout

```
core-graph/
├── docs/           Architecture, compliance, ontology, operations
├── schema/         SQL migrations (numbered) and seed data
├── policies/       Authorization policies (Cerbos YAML)
├── ingest/         Satellite connectors, NER pipeline, graph writer, DLQ
├── api/            MCP server, REST API, authz (SpiceDB/Cerbos), connection pool
├── deploy/         Docker Compose (dev), Kustomize (lab/prod), NATS config
├── evidence/       Signing, hash chains, MinIO WORM, Rekor integration
├── tests/          Schema, RLS, ingest, and auth tests
└── scripts/        Bootstrap, validation, MinIO init
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
