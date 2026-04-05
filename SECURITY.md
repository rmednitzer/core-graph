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

### Authorization (three-layer model)

1. **Cerbos (ABAC)** -- attribute-based access control evaluating TLP clearance,
   role policies, time-of-day, and source-IP constraints
2. **SpiceDB (ReBAC)** -- relationship-based access control for investigation
   compartments, team ownership, and delegation chains
3. **PostgreSQL RLS** -- row-level security filtering at the database engine
   level, unforgeable from the application layer

Even if application code has a bug, the database engine will not return rows
the session is not authorised to see.

### Data classification

- TLP markings (CLEAR, GREEN, AMBER, AMBER+STRICT, RED) enforced at the
  RLS layer on every query
- IAM data has a TLP:AMBER floor -- no IAM vertex is visible below TLP:AMBER
- Session variables (`app.max_tlp`, `app.allowed_compartments`) set after
  Cerbos/SpiceDB checks pass

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
