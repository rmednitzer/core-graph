# Core-Graph

A converged graph-vector knowledge platform built on PostgreSQL with Apache AGE
and pgvector. Designed for EU-sovereign deployment with security, compliance,
and operational assurance as structural properties.

![CI](https://github.com/rmednitzer/core-graph/actions/workflows/test.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

## What it does

core-graph is a canonical convergence point for heterogeneous security and
infrastructure data. Satellite systems publish structured entities through NATS
JetStream into a PostgreSQL hub where they are stored as a graph (Apache AGE),
enriched with vector embeddings (pgvector), and exposed through multiple
interfaces.

### Data domains (eight ontology layers)

| Layer | Description | Standards |
|---|---|---|
| **Threat intelligence** | TTPs, indicators, campaigns, threat actors, malware, vulnerabilities | STIX 2.1, MITRE ATT&CK |
| **Security events** | Normalised alerts and detections from Wazuh, EDR, IDS/IPS | OCSF 1.1 |
| **OSINT** | Feed aggregation, entity extraction, deduplication | STIX 2.1 |
| **Audit and compliance** | Evidence chains, control mapping (NIS2, DORA, ISO 27001, BSI) | OSCAL |
| **AI memory** | Agent conversation context, reasoning traces, semantic embeddings | MCP-aligned |
| **Forensic timelines** | Bitemporal facts, chain of custody, immutable evidence | CASE/UCO, STIX 2.1 |
| **Infrastructure and assets** | CMDB, network inventory, monitoring alerts | Netbox/Prometheus aligned |
| **Identity and access management** | IAM vertices with TLP:AMBER floor, Keycloak sync | Keycloak/Cerbos aligned |

### Interfaces

- **MCP server** -- primary AI agent interface (tool-based graph queries, semantic search)
- **REST API** -- FastAPI-based CRUD and query endpoints for human consumers
- **TAXII 2.1** -- federated threat intelligence sharing with partner organisations

## Status

**Alpha:** local development stack operational, schema stable, ingest pipeline
functional, Helm chart and ArgoCD manifests ready.

## Prerequisites

- Python 3.12+
- Docker and Docker Compose (for the local dev stack)
- PostgreSQL 16+ with [Apache AGE](https://age.apache.org/) and
  [pgvector](https://github.com/pgvector/pgvector) (provided by the dev stack)
- NATS Server 2.10+ (provided by the dev stack)

## Quick start

```bash
git clone https://github.com/rmednitzer/core-graph.git
cd core-graph

# Install Python dependencies
pip install -e ".[dev,test]"

# Start the full dev stack (includes API on :8000)
make up

# Run migrations and load reference data
make migrate
make seed
```

The dev stack (`make up`) starts all services including the REST API on `:8000`.
To run services **locally instead** (e.g. for hot-reload development), stop the
stack first and start only infrastructure, then run the API outside Docker:

```bash
make down
docker compose -f deploy/docker/docker-compose.yml up -d postgres nats valkey spicedb cerbos minio

make serve          # REST API on :8000 (uvicorn --reload)
make mcp            # MCP server
make graph-writer   # Ingest graph writer
```

## Deployment

### Docker Compose (development)

```bash
make up       # start
make down     # stop
make reset    # drop + recreate database, re-run migrations and seeds
```

### Helm chart (Kubernetes)

The Helm chart in `deploy/k8s/helm/` bundles the API, graph writer, PostgreSQL,
NATS JetStream, and Valkey. Each dependency can be disabled to point at external
services.

```bash
# Lab (bundled dependencies, 2 API replicas)
helm install cg deploy/k8s/helm/

# Production (HA replicas, autoscaling, resource limits)
helm install cg deploy/k8s/helm/ -f deploy/k8s/helm/values-prod.yaml

# External PostgreSQL
helm install cg deploy/k8s/helm/ \
  --set postgres.enabled=false \
  --set postgres.external.host=my-pg.example.com \
  --set postgres.external.password=secret
```

See `deploy/k8s/helm/values.yaml` for the full configuration reference.

### ArgoCD

Pre-built Application manifests are provided for both environments:

```bash
# Lab -- auto-sync, self-heal, CreateNamespace=true
kubectl apply -f deploy/k8s/helm/argocd/application-lab.yaml

# Production -- manual sync, change-control compliant
kubectl apply -f deploy/k8s/helm/argocd/application-prod.yaml
```

### Air-gapped install (Zarf)

[Zarf](https://zarf.dev/) packages the Helm chart and all container images into
a single signed tarball for disconnected clusters.

```bash
# Build (internet-connected machine)
zarf package create --confirm

# Deploy (air-gapped cluster)
zarf package deploy zarf-package-core-graph-amd64-0.1.0.tar.zst --confirm

# Deploy with production profile
zarf package deploy zarf-package-core-graph-amd64-0.1.0.tar.zst \
  --components="core-graph,prod-profile" --confirm
```

## Architecture

```
  Satellites             NATS JetStream          Ingest Pipeline
  ----------             --------------          ---------------

  Wazuh (SIEM)    ──┐
  OpenCTI (TIP)   ──┤                        ┌─────────────────┐
  MISP (IOC DB)   ──┼──►  NATS JetStream  ──►│  NER + Entity   │
  OSINT Feeds     ──┤     (at-least-once)     │  Resolution +   │
  Netbox (CMDB)   ──┤                         │  Graph Writer   │
  Prometheus      ──┤                         └────────┬────────┘
  Keycloak (IdP)  ──┘                                  │
                                                       ▼
                                          ┌────────────────────────┐
                                          │    PostgreSQL 16+      │
                                          │  ┌────────┐ ┌────────┐ │
                                          │  │  AGE   │ │pgvector│ │
                                          │  │(graph) │ │(embed.)│ │
                                          │  └────────┘ └────────┘ │
                                          │  RLS · pgAudit · cron  │
                                          │  Bitemporal model      │
                                          └────────────┬───────────┘
                                                       │
                    ┌──────────────────────────────────┼──────────┐
                    │             API Layer            │          │
                    │   Cerbos (ABAC) + SpiceDB (ReBAC)          │
                    ├──────────┬───────────┬─────────────────────┤
                    │ MCP Server│ REST API │ TAXII 2.1           │
                    │(AI agents)│ (humans) │ (sharing)           │
                    └──────────┴───────────┴─────────────────────┘

  Evidence chain: audit_log ──► hash chain ──► MinIO WORM ──► cosign ──► Rekor
```

### Key design decisions

- **PostgreSQL is the core.** No Neo4j, no ArangoDB. Apache AGE for graph
  (openCypher), pgvector for embeddings (HNSW).
- **NATS JetStream** as the message bus. At-least-once delivery, dead-letter
  queue with retry and archive.
- **Three-layer authorization:** Cerbos (ABAC) evaluates TLP clearance and role
  policies, SpiceDB (ReBAC) evaluates compartment membership, PostgreSQL RLS
  enforces at the engine level. Even buggy application code cannot leak data.
- **Bitemporal model:** four timestamps per fact (`t_valid`, `t_invalid`,
  `t_recorded`, `t_superseded`). Facts are invalidated, never deleted.
- **Evidence integrity:** append-only audit log, SHA-256 hash chains, Merkle
  roots with RFC 3161 timestamps, MinIO WORM storage, cosign signing, Rekor
  transparency log.
- **EU-sovereign:** all infrastructure runs on EU providers (Hetzner, self-hosted
  registries). No US cloud dependencies in production.

## Development

### Make targets

| Target | Description |
|---|---|
| `make up` | Start Docker Compose dev stack |
| `make down` | Stop dev stack |
| `make reset` | Drop, recreate, migrate, and seed database |
| `make migrate` | Run numbered SQL migrations |
| `make seed` | Load reference data (MITRE ATT&CK, STIX, roles) |
| `make serve` | REST API on :8000 (uvicorn --reload) |
| `make mcp` | Run MCP server |
| `make graph-writer` | Run graph writer worker |
| `make psql` | Connect to dev database interactively |
| `make test` | Run all tests (pytest + RLS enforcement) |
| `make integration-test` | Run integration tests only |
| `make lint` | Lint Python (ruff) and YAML policies |
| `make bench` | Run performance benchmarks (NER, traversal, throughput) |
| `make verify-chain` | Verify audit log hash chain |
| `make verify-merkle` | Verify Merkle root chain |
| `make stamp-merkle` | Request RFC 3161 timestamps for Merkle roots |
| `make helm-validate` | Lint and template Helm charts |
| `make deploy-lint` | Validate all deployment artifacts |

### Running tests

```bash
# All tests (unit + RLS enforcement)
make test

# Integration tests (requires running Docker stack)
make integration-test

# Specific test file
pytest tests/skills/test_asset_skills.py -v

# Linting
make lint
```

## Repository layout

```
core-graph/
├── api/                 API layer
│   ├── rest/            FastAPI REST endpoints + middleware (OIDC, metrics, logging)
│   ├── mcp/             MCP server, skill registry, query templates
│   │   ├── skills/      Skill implementations (asset, compliance, identity, threat)
│   │   └── tools/       MCP tools (cypher query, entity resolve, vector search, ...)
│   ├── taxii/           TAXII 2.1 server for threat intel sharing
│   ├── authz/           SpiceDB (ReBAC) and Cerbos (ABAC) client modules
│   ├── utils/           AGE query guard, Cypher safety validation
│   └── db.py            Shared connection pool (psycopg-pool)
├── ingest/              Ingest pipeline
│   ├── connectors/      Satellite adapters (Wazuh, OpenCTI, MISP, OSINT, Netbox,
│   │                    Prometheus, Keycloak) -- all extend AdapterBase
│   ├── ner/             Named entity recognition (tier 1: regex + STIX patterns)
│   ├── resolver/        Entity resolution and deduplication
│   ├── dlq/             Dead-letter queue processor
│   └── graph_writer.py  Batch graph writer with bitemporal versioning
├── schema/
│   ├── migrations/      Numbered SQL files (001_ through 019_), idempotent
│   └── seed/            Reference data (MITRE ATT&CK, STIX vocabularies, roles)
├── policies/            Cerbos YAML policies (threat entities, evidence, incidents, IAM)
├── evidence/            Evidence integrity
│   ├── chain/           Merkle root computation and hash chain verification
│   └── signing/         cosign signing, MinIO WORM storage, RFC 3161 timestamps
├── deploy/
│   ├── docker/          Docker Compose dev stack + hardened PostgreSQL config
│   ├── k8s/             Helm chart, Kustomize overlays, ArgoCD manifests
│   ├── nats/            NATS server config (dev + prod)
│   └── grafana/         Dashboards and provisioning
├── tests/               Schema, RLS, ingest, integration, skills, TAXII tests
├── scripts/             Bootstrap, validation, benchmarks, MinIO init
├── docs/                Architecture, compliance, ontology, operations, runbooks
└── zarf.yaml            Air-gapped deployment package definition
```

## Documentation

Detailed documentation lives in [`docs/`](docs/):

| Area | Documents |
|---|---|
| **Architecture** | [Overview](docs/architecture/overview.md), [Authorization model](docs/architecture/authorization-model.md), [RLS + AGE integration](docs/architecture/rls-age-integration.md), [IAM layer](docs/architecture/iam-layer.md), [Data residency](docs/architecture/data-residency.md) |
| **Ontology** | [Schema design](docs/ontology/schema-design.md), [STIX mapping](docs/ontology/stix-mapping.md), [OCSF normalization](docs/ontology/ocsf-normalization.md) |
| **Compliance** | [NIS2 controls](docs/compliance/nis2-controls.md), [BSI IT-Grundschutz](docs/compliance/bsi-grundschutz-map.md) |
| **Operations** | [Backup and restore](docs/operations/backup-restore.md), [PostgreSQL hardening](docs/operations/postgresql-hardening.md), [Break-glass procedure](docs/operations/break-glass.md), [PG major upgrade](docs/operations/pg-major-upgrade.md) |
| **Runbooks** | [Audit chain broken](docs/operations/runbooks/audit-chain-broken.md), [Ingest pipeline stalled](docs/operations/runbooks/ingest-pipeline-stalled.md), [DLQ overflow](docs/operations/runbooks/dlq-overflow.md), [RLS misconfiguration](docs/operations/runbooks/rls-misconfiguration.md) |
| **Skills** | [MCP skill registry](docs/skills/README.md) |

## Conventions

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/)
  with scopes: `feat:`, `fix:`, `docs:`, `schema:`, `policy:`, `deploy:`,
  `test:`, `skill:`
- **Migrations:** Numbered SQL files (`001_`, `002_`, ...). No ORM.
- **Security:** Parameterised SQL, AGE query templates (no string concatenation),
  RLS enforcement, Cerbos/SpiceDB authorization on every request.
- **Format:** SI units, ISO 8601 dates (YYYY-MM-DD), 24h time, UTC unless
  explicitly local.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow, code style, and
PR guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security design
overview.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

The core path (PostgreSQL + AGE + pgvector + NATS + Cerbos + cosign) is
entirely Apache 2.0 / MIT / BSD / PostgreSQL Licence. Satellite components
carry their own licences (GPL, AGPL) and operate as external services, not
embedded in redistributable code.
