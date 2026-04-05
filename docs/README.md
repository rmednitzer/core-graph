# Documentation

## Architecture

- [Overview](architecture/overview.md) -- hub-and-spoke topology, core
  components, ontology layers, bitemporal model, evidence integrity pattern,
  implementation roadmap
- [Authorization model](architecture/authorization-model.md) -- three-layer
  authorization (Cerbos ABAC, SpiceDB ReBAC, PostgreSQL RLS), TLP clearance,
  role hierarchy, break-glass procedures
- [RLS + AGE integration](architecture/rls-age-integration.md) -- how Row-Level
  Security applies to Apache AGE graph traversals, edge denormalisation,
  defence-in-depth strategy
- [IAM layer](architecture/iam-layer.md) -- Keycloak as authoritative source,
  delta-sync via Valkey, TLP:AMBER floor enforcement, `Principal--same_as--ThreatActor`
  attribution rules
- [Data residency](architecture/data-residency.md) -- EU-sovereign controls,
  approved providers (Hetzner, Quad9, PTB), self-hosted registries and proxies,
  prohibited services

## Ontology

- [Schema design](ontology/schema-design.md) -- eight-layer unified ontology,
  cross-layer canonical entities, bitemporal model, entity resolution pattern
- [STIX mapping](ontology/stix-mapping.md) -- STIX 2.1 SDOs to graph vertices,
  SROs to edges, SCOs to canonical entities, common properties
- [OCSF normalization](ontology/ocsf-normalization.md) -- OCSF category-to-vertex
  mapping, field mapping, severity-to-TLP mapping, edge creation rules

## Compliance

- [NIS2 controls](compliance/nis2-controls.md) -- mapping of NIS2 Article 21
  measures to platform implementations
- [BSI IT-Grundschutz](compliance/bsi-grundschutz-map.md) -- mapping of BSI
  modules to platform capabilities with evidence artefacts

## Operations

- [Backup and restore](operations/backup-restore.md) -- pgBackRest strategy,
  WAL archiving, encryption, monthly restore tests, RPO/RTO targets
- [PostgreSQL hardening](operations/postgresql-hardening.md) -- CIS Benchmark
  alignment, TLS, authentication, auditing, memory tuning, monitoring queries
- [Break-glass procedure](operations/break-glass.md) -- Shamir secret sharing,
  time-limited access, mandatory audit trail, automatic revocation
- [PostgreSQL major upgrade](operations/pg-major-upgrade.md) -- dump/restore
  procedure for AGE compatibility, pre/post upgrade checklists

### Runbooks

- [Audit chain broken](operations/runbooks/audit-chain-broken.md) -- diagnosing
  hash chain failures, evidence preservation, NIS2 notification
- [Ingest pipeline stalled](operations/runbooks/ingest-pipeline-stalled.md) --
  NATS consumer lag, graph writer troubleshooting, DLQ depth checks
- [DLQ overflow](operations/runbooks/dlq-overflow.md) -- error classification,
  root cause analysis, bulk resolution, reprocessing
- [RLS misconfiguration](operations/runbooks/rls-misconfiguration.md) -- policy
  predicate errors, session variable issues, testing procedures

## MCP skills

- [Skill registry](skills/README.md) -- skill architecture, implementation
  guide, parameter schemas, confidence scoring, available skills
