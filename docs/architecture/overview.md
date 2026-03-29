# Architecture overview

core-graph is a converged graph-vector knowledge platform built on PostgreSQL.
It ingests structured entities from satellite security systems through NATS
JetStream, stores them in a graph (Apache AGE) and vector (pgvector) enabled
PostgreSQL instance, and exposes them to AI agents via MCP, to humans via
REST API, and to partner organisations via TAXII 2.1.

Design goals: EU-sovereign, single-engineer operable, auditable,
evidence-producing.

## Hub-and-spoke topology

The architecture follows a hub-and-spoke pattern. Satellite systems (left)
publish events and entities into NATS JetStream. The ingest pipeline consumes
from NATS, performs NER, entity resolution, and graph writing into the
PostgreSQL hub. Consumers (right) query through an API layer that enforces
authorization at every tier.

```text
  Satellites                Message Bus            Ingest                   Core Store
  ----------                -----------            ------                   ----------

  +-----------+
  |  Wazuh    |---+
  |  (SIEM)   |   |
  +-----------+   |
                  |
  +-----------+   |      +----------------+     +---------------------+
  |  OpenCTI  |---+----->|                |     |                     |
  |  (TIP)    |   |      |     NATS       |     |   Ingest Pipeline   |
  +-----------+   |      |   JetStream    |---->|                     |
                  |      |                |     |  +---------------+  |
  +-----------+   |      |  +-----------+ |     |  | Tier 1: Regex |  |
  |   MISP    |---+----->|  | Subjects: | |     |  | + STIX patt.  |  |
  |  (IOC DB) |   |      |  | ingest.>  | |     |  +---------------+  |
  +-----------+   |      |  | dlq.>     | |     |  | Tier 2: spaCy |  |
                  |      |  | audit.>   | |     |  | NER models    |  |
  +-----------+   |      |  +-----------+ |     |  +---------------+  |
  |   OSINT   |---+----->|                |     |  | Tier 3: LLM   |  |
  |   Feeds   |   |      +-------+--------+     |  | extraction    |  |
  +-----------+   |              |               |  +---------------+  |
                  |              |               |                     |
  +-----------+   |              v               |  Entity Resolution  |
  |  Netbox   |---+      +------+-------+       |  + Graph Writer     |
  |  (CMDB)   |   |      | Dead-letter  |       +----------+----------+
  +-----------+   |      | queue (DLQ)  |                  |
                  |      +--------------+                  |
  +-----------+   |                                        v
  |Prometheus |---+                          +------------+-------------+
  |(Alerting) |        +-------------------+ |                          |
  +-----------+        |   Valkey Cache    |<|       PostgreSQL 16+     |
                       |                   | |                          |
                       | - Session state   | |  +--------------------+  |
                       | - Rate limiting   | |  | Apache AGE         |  |
                       | - Hot query cache | |  | (openCypher graph) |  |
                       +-------------------+ |  +--------------------+  |
                                             |  +--------------------+  |
                                             |  | pgvector (HNSW)    |  |
  +-------------------+                      |  | (embeddings)       |  |
  |  Cerbos (ABAC)    |---+                  |  +--------------------+  |
  |  TLP clearance,   |   |                  |  +--------------------+  |
  |  role policies    |   |                  |  | RLS engine         |  |
  +-------------------+   |                  |  | TLP + compartment  |  |
                          v                  |  | enforcement        |  |
  +-------------------+  ++----------+       |  +--------------------+  |
  |  SpiceDB (ReBAC)  |->| API Layer |<-----+|  +--------------------+  |
  |  Compartments,    |  | (FastAPI) |       |  | Bitemporal model   |  |
  |  team ownership   |  +--+--+--+--+       |  | t_valid/t_invalid  |  |
  +-------------------+     |  |  |          |  | t_recorded/t_super |  |
                            |  |  |          |  +--------------------+  |
               +------------+  |  +------+   +-------------------------+
               |               |         |
         +-----+------+ +-----+----+ +--+--------+
         | MCP Server | | REST API | | TAXII 2.1 |
         | (AI agents)| | (humans) | | (sharing) |
         +------------+ +----------+ +-----------+

  Evidence Chain
  --------------
  +-------------------+       +-------------------------+
  |  MinIO WORM       |       |  cosign / Rekor         |
  |  (object-lock     |<----->|  (keyless signing &     |
  |   evidence store) |       |   transparency log)     |
  +-------------------+       +-------------------------+
```

## Core components

| Component | Role | Licence |
|---|---|---|
| PostgreSQL 16+ | Core relational database engine; hosts graph, vector, bitemporal tables, and RLS | PostgreSQL Licence (permissive) |
| Apache AGE 1.5+ | Graph extension providing openCypher query language over PostgreSQL storage | Apache 2.0 |
| pgvector 0.7+ | HNSW-indexed vector similarity search for semantic embeddings | PostgreSQL Licence |
| NATS JetStream | Persistent message bus connecting satellite systems to the ingest pipeline; at-least-once delivery | Apache 2.0 |
| Cerbos 0.35+ | Attribute-based access control engine; evaluates TLP clearance, role policies, and contextual constraints | Apache 2.0 |
| SpiceDB 1.33+ | Relationship-based access control engine; manages investigation compartments, team ownership, delegation | Apache 2.0 |
| cosign | Keyless signing of evidence artefacts using Sigstore OIDC flow; no long-lived keys | Apache 2.0 |
| Rekor | Append-only transparency log providing tamper-evident, publicly verifiable record of signatures | Apache 2.0 |
| MinIO | S3-compatible object storage configured in WORM (object-lock compliance) mode for evidence retention | AGPL 3.0 |
| Valkey 8+ | In-memory cache for session state, rate limiting, and hot query results; Redis-compatible fork | BSD 3-Clause |
| Harbor 2+ | Self-hosted OCI container registry for EU data residency compliance; no Docker Hub pulls in production | Apache 2.0 |

## Seven ontology layers

core-graph organises knowledge into seven typed layers. Each layer has its own
AGE graph label namespace, standards mapping, and retention policy. All layers
share the bitemporal model described below.

| Layer | Description | Primary standards | Retention |
|---|---|---|---|
| **Threat intelligence** | TTPs, indicators, campaigns, threat actors, malware families, vulnerabilities. Forms the backbone of the knowledge graph. | STIX 2.1, MITRE ATT&CK | Indefinite (bitemporally versioned) |
| **Security events** | Normalised alerts and detections from Wazuh, EDR, IDS/IPS. High-volume, time-series oriented. | OCSF 1.1 | 13 months hot, 7 years cold (compressed, queryable) |
| **OSINT** | Open-source intelligence from feeds, social media, paste sites, dark web monitors. Correlated with threat intel layer via entity resolution. | STIX 2.1 (observed-data, report) | Indefinite (bitemporally versioned) |
| **Audit and compliance** | Policy evaluations, compliance check results, control mappings for NIS2, DORA, and ISO 27001. Machine-readable evidence for auditors. | OSCAL, custom schemas | 10 years (regulatory minimum per DORA Art. 17) |
| **AI memory** | Agent conversation context, reasoning traces, tool invocations, semantic embeddings. Enables continuity across MCP sessions. | Custom (MCP-aligned) | 90 days hot, 2 years archive |
| **Forensic timeline** | Ordered evidence chains for incident response. Immutable once sealed. Backed by MinIO WORM and cosign signatures. | CASE/UCO, STIX 2.1 | Indefinite (sealed, WORM-backed) |
| **Infrastructure and assets** | Hosts, networks, sites, interfaces, services, and monitoring alerts. Populated from Netbox (CMDB) and Prometheus (alerting). | Custom (Netbox/Prometheus aligned) | Indefinite (bitemporally versioned) |

### Bitemporal model

Every fact in every layer carries four timestamps:

- **t_valid** -- when the fact became true in the real world
- **t_invalid** -- when the fact ceased to be true (NULL if still valid)
- **t_recorded** -- when the fact was recorded in core-graph
- **t_superseded** -- when a newer version of this fact was recorded (NULL if current)

Facts are invalidated, never physically deleted. This preserves full audit
history and allows point-in-time queries at any moment in both real-world time
and system time.

## Authorization model

core-graph uses a dual-engine authorization architecture with three enforcement
layers. See [authorization-model.md](authorization-model.md) for full details.

```text
Request --> Cerbos (ABAC)   --> "Is this role cleared for TLP:AMBER?"
        --> SpiceDB (ReBAC)  --> "Is this user in compartment investigation-42?"
        --> PostgreSQL RLS   --> rows filtered at engine level, unforgeable
```

1. **Cerbos** evaluates attribute-based policies: TLP marking clearance,
   role-to-resource permissions, time-of-day constraints, and source-IP
   restrictions.
2. **SpiceDB** evaluates relationship-based checks: investigation compartment
   membership, delegation chains, team ownership, and cross-team sharing
   permissions.
3. **PostgreSQL RLS** enforces the final result. Session variables
   (`app.max_tlp`, `app.allowed_compartments`) are set by the application after
   Cerbos and SpiceDB checks pass. RLS policies filter every query, including
   those issued through AGE graph traversals.

This layered design means that even if application code has a bug, the database
engine itself will not return rows the session is not authorised to see. The
database is the last line of defence, and it is unforgeable from the
application layer.

## Evidence integrity pattern

For forensic and compliance use cases, core-graph produces tamper-evident
evidence chains. This pattern satisfies NIS2 incident reporting requirements
and DORA evidence preservation obligations.

```text
1. Fact written to PostgreSQL  -->  append-only audit_log table
2. Hash chain computed         -->  SHA-256 of (previous_hash || row_content)
3. Artefact exported to MinIO  -->  object-lock WORM bucket (compliance mode)
4. Artefact signed             -->  cosign keyless signing (Sigstore OIDC)
5. Signature logged            -->  Rekor transparency log entry
```

**Properties achieved:**

- **Append-only**: The `audit_log` table uses a trigger-enforced insert-only
  policy. No UPDATE or DELETE is permitted. The trigger fires BEFORE any
  UPDATE or DELETE and raises an exception unconditionally.
- **Hash chain**: Each entry includes a SHA-256 hash computed over
  `previous_hash || canonical_json(row_content)`. This forms a verifiable
  chain. Any tampering -- insertion, modification, or deletion of a row --
  breaks the chain from that point forward.
- **Immutable storage**: MinIO WORM mode with object-lock (compliance mode, not
  governance mode) prevents overwrite or deletion until the retention period
  expires. Not even the MinIO root user can delete locked objects.
- **Non-repudiation**: cosign signs artefacts using the operator's OIDC
  identity (tied to the IdP). No long-lived signing keys to manage, rotate,
  or potentially compromise.
- **Public verifiability**: Rekor entries allow any party to independently
  verify that a specific artefact existed at a specific time, without needing
  access to the core-graph instance itself.

### Verification workflow

```text
# Verify a single evidence artefact
cosign verify-blob --certificate-identity <operator-email> \
  --certificate-oidc-issuer <idp-url> \
  --bundle evidence.sigstore.json \
  evidence.json

# Verify the hash chain
python -m evidence.verify_chain --from-audit-log --check-minio
```

## Phased implementation roadmap

### Phase 1 -- Foundation ✅

Target: local development environment fully functional, schema stable.

- ✅ PostgreSQL schema: bitemporal tables, AGE graph labels, pgvector HNSW indexes
- ✅ Local development stack: Docker Compose with PostgreSQL, NATS, Valkey, MinIO
- ✅ Ingest foundation: NATS consumer skeleton, tier-1 NER (regex + STIX pattern matching)
- ✅ MCP server skeleton: tool registration, basic graph query, semantic search stubs
- ✅ RLS policies: TLP enforcement at the engine level, session variable pipeline
- ✅ Seed data: MITRE ATT&CK (Enterprise, ICS, Mobile), STIX vocabularies, role definitions
- ✅ Migration framework: numbered SQL files, idempotent execution, rollback support
- ✅ Basic test suite: schema validation, RLS enforcement tests, migration idempotency

### Phase 2 -- Ingest pipeline and evidence ✅

Target: satellite systems connected, evidence chain operational.

- ✅ Full satellite connectors: Wazuh, OpenCTI, MISP, OSINT feeds, Netbox, Prometheus
- ✅ Entity resolution: deduplication, merging, confidence scoring, provenance tracking
- ✅ Graph writer: batch upsert with bitemporal versioning, conflict resolution
- ✅ Evidence signing pipeline: cosign integration, Rekor log submission
- ✅ MinIO WORM configuration: object-lock policies, retention rules, lifecycle management
- ✅ Cerbos policy library: TLP, role, time-based, and source-IP policies
- ✅ SpiceDB schema: investigation compartments, team ownership, delegation relations
- ✅ Dead-letter queue processing: retry logic, alerting, manual review workflow
- NER tiers 2 and 3: spaCy NER models, LLM-assisted entity extraction (planned)

### Phase 3 -- Deployment and federation (in progress)

Target: production-grade Kubernetes deployment, inter-organisational sharing.

- ✅ Kubernetes deployment: Helm chart with lab and production profiles, ArgoCD manifests
- ✅ TAXII 2.1 server: federated threat intelligence sharing with partner organisations
- ✅ Air-gapped deployment: Zarf package for disconnected clusters
- ✅ Monitoring stack: Prometheus metrics, Grafana dashboards
- Horizontal read scaling: PostgreSQL streaming replicas with read routing
- NATS cluster: multi-node JetStream for message bus resilience
- EU data residency controls: Harbor registry, self-hosted package proxies, DNS/NTP sovereignty
- Backup and restore: automated PostgreSQL backups to Hetzner Object Storage (EU)

### Phase 4 -- Production hardening and compliance

Target: auditable, certified, and operationally resilient.

- Penetration testing and security audit by external assessor
- NIS2 compliance mapping and automated evidence generation
- DORA operational resilience testing (scenario-based)
- ISO 27001 control alignment and gap remediation
- Performance benchmarking: graph traversal latency, ingest throughput, query P99
- Disaster recovery procedures and regular failover testing
- Operator runbooks and incident response playbooks
- Compliance certification preparation and auditor documentation package
