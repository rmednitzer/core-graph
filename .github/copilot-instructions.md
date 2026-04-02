# core-graph — Copilot instructions

## Project

core-graph is a converged graph-vector knowledge platform. PostgreSQL 16+ with
Apache AGE (openCypher graph queries) and pgvector (HNSW vector similarity
search) is the canonical store. Satellite systems (Wazuh, OpenCTI, MISP,
OpenSearch, MinIO) feed structured entities through NATS JetStream into the
core.

## Stack

- **Database**: PostgreSQL 16+ / Apache AGE / pgvector
- **Message bus**: NATS JetStream
- **Authorisation**: Cerbos (ABAC) + SpiceDB (ReBAC)
- **Evidence integrity**: cosign + Rekor + MinIO WORM
- **Language**: Python 3.12+, SQL (no ORM), YAML (Cerbos policies)

## Style rules

- Python: ruff, type hints required, conventional commits, smallest safe
  increments
- SQL: lowercase keywords, 4-space indentation, parameterised queries only
- YAML: 2-space indentation
- Commits: `feat:`, `fix:`, `docs:`, `schema:`, `policy:`, `deploy:`, `test:`,
  `chore:`

## Do not

- Add Neo4j, ArangoDB, or any alternative graph database
- Replace NATS with Kafka or RabbitMQ
- Use an ORM for schema management
- Bypass RLS policies or Cerbos evaluation
- Commit secrets, keys, or credentials
- Use string concatenation in Cypher queries — use query templates

## Testing

- Python: pytest (`tests/`)
- Schema / RLS: SQL scripts (`tests/schema/`, `tests/rls/`)
- Policies: Cerbos test suites (`tests/auth/`)
- All tests run in CI on push and pull_request to `main`

## Security invariants

- Row-Level Security enforces TLP markings at the engine level
- Cerbos evaluates every action before it reaches the database
- All SQL uses parameterised queries (CVE-2022-45786 mitigation)
- Cypher queries through AGE use query templates, not string concatenation
- Bitemporal facts are invalidated, never deleted
- Cypher labels interpolated into AGE queries must pass validate_label()
  from api/utils/cypher_safety.py (regex: `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
