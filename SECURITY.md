# Security policy

## Reporting vulnerabilities

If you discover a security vulnerability in this project, please report it
responsibly. Do not open a public issue.

Email: <security@blackphoenix.org>

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected component (schema, API, ingest, deploy)
- Potential impact

You will receive an acknowledgement within 48 hours.

## Supported versions

Only the latest commit on `main` is supported. This project is in alpha.

## Security architecture

core-graph enforces security as a structural property across multiple layers:

### Authorization (target model and current enforcement)

The target architecture is a three-layer model:

1. **Cerbos (ABAC)** -- attribute-based access control evaluating TLP clearance,
   role policies, time-of-day, and source-IP constraints
2. **SpiceDB (ReBAC)** -- relationship-based access control for investigation
   compartments, team ownership, and delegation chains
3. **PostgreSQL RLS** -- row-level security filtering at the database engine
   level, unforgeable from the application layer

Current enforcement (codified by ADR-0006):

- **Reads** (REST `/query`, `/search`, `/entities`, `/stix`; MCP read tools;
  TAXII collection endpoints): only Layer 3 (PostgreSQL RLS) is enforced at
  runtime. TLP clearance is gated by the `app.max_tlp` session variable set
  on every connection acquired from `api.db.get_connection`. Compartment
  scoping is currently enforced at the Cypher template layer via
  `app.allowed_compartments`, not by RLS.
- **Writes** to the `Principal--same_as--ThreatActor` edge (identity
  attribution): Layer 1 (Cerbos) is enforced -- the `cg_ciso` role check
  via `policies/resource/identity_attribution.yaml` runs before any DB
  operation, and the operation fails closed if Cerbos is unreachable.
  Layer 3 (RLS) also applies.
- **Layer 2 (SpiceDB)**: schema (`api/authz/schema.zed`) and client
  (`api/authz/spicedb.py`) are defined but not yet invoked from any request
  path. Status: pending integration (see ADR-0006).

Even if application code has a bug, the database engine will not return rows
the session is not authorised to see -- RLS is the unforgeable floor across
all layers.

### Data classification

- TLP markings (CLEAR, GREEN, AMBER, AMBER+STRICT, RED) enforced at the
  RLS layer on every query
- IAM data has a TLP:AMBER floor -- no IAM vertex is visible below TLP:AMBER
- Session variables (`app.max_tlp`, `app.allowed_compartments`) are set on
  every connection acquired from `api.db.get_connection`, derived from
  the OIDC-attested `CallerIdentity`. Cerbos is invoked before the session
  is established only on the identity-attribution write path; on reads
  the RLS layer is the sole runtime gate

### Query safety

- All SQL uses parameterised queries (CVE-2022-45786 mitigation)
- AGE Cypher queries use query templates, not string concatenation
- Labels and relationship types validated via `validate_label()` before
  interpolation
- Statement timeouts enforced per role

### Evidence integrity

- Append-only `audit_log` table (trigger-enforced, no UPDATE/DELETE)
- SHA-256 hash chains with Merkle root verification
- RFC 3161 timestamps for non-repudiation
- MinIO WORM storage (object-lock compliance mode)
- cosign keyless signing via Sigstore OIDC
- Rekor transparency log for public verifiability

### Operational security

- No secrets in the repository (environment variables or credential stores)
- SCRAM-SHA-256 for PostgreSQL authentication
- TLS 1.3 for all connections in production
- Network policies restricting pod-to-pod communication in Kubernetes
- Break-glass procedure with 2-of-3 Shamir secret sharing, 4-hour maximum
  duration, and mandatory post-incident review

## Further reading

- [Architecture overview](docs/architecture/overview.md)
- [Authorization model](docs/architecture/authorization-model.md)
- [RLS + AGE integration](docs/architecture/rls-age-integration.md)
- [PostgreSQL hardening](docs/operations/postgresql-hardening.md)
- [Break-glass procedure](docs/operations/break-glass.md)
