# Architecture overview

> TODO: Migrate full architecture design from initial research into this document.

## Hub-and-spoke topology

Satellite systems feed structured entities through NATS JetStream into the
PostgreSQL graph-vector core.

```text
Wazuh ──┐
OpenCTI ─┤
MISP ────┤──► NATS JetStream ──► NER Pipeline ──► PostgreSQL (AGE + pgvector)
OSINT ───┤                                              │
Logs ────┘                                         MCP Server ──► AI Agents
                                                        │
                                                   REST / GraphQL
```

## Core components

| Component | Role | Licence |
| --- | --- | --- |
| PostgreSQL 16+ | Core database engine | PostgreSQL Licence |
| Apache AGE | Graph extension (openCypher) | Apache 2.0 |
| pgvector | Vector similarity search | PostgreSQL Licence |
| NATS JetStream | Message broker | Apache 2.0 |
| Cerbos | ABAC authorization (TLP) | Apache 2.0 |
| SpiceDB | ReBAC authorization (compartments) | Apache 2.0 |
| cosign / Rekor | Evidence signing, transparency log | Apache 2.0 |

## Key design decisions

- PostgreSQL over Neo4j CE (no RBAC) and ArangoDB (BSL 1.1)
- Native RLS for TLP enforcement at the engine level
- Bitemporal modeling: four timestamps per fact
- STIX 2.1 as canonical threat intelligence data model
- OCSF as event normalisation layer
- MCP as the primary AI agent interface
