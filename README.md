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

## Deployment

### Helm chart

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
# Lab — auto-sync, self-heal, CreateNamespace=true
kubectl apply -f deploy/k8s/helm/argocd/application-lab.yaml

# Production — manual sync, change-control compliant
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
├── deploy/         Docker Compose (dev), Kustomize, Helm chart, ArgoCD manifests
├── evidence/       Signing, hash chains, MinIO WORM, Rekor integration
├── tests/          Schema, RLS, ingest, and auth tests
├── scripts/        Bootstrap, validation, MinIO init
└── zarf.yaml       Zarf package definition (air-gapped deployment)
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
