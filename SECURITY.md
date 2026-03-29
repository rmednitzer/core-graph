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

Only the latest commit on `main` is supported. This project is pre-alpha.

## Security design

This project enforces security as a structural property:

- PostgreSQL Row-Level Security enforces data classification (TLP markings)
- Cerbos + SpiceDB handle authorization decisions
- All SQL uses parameterised queries
- Evidence integrity via cryptographic hash chains and cosign signing
- No secrets in repository (use environment variables or credential stores)

See [docs/architecture/overview.md](docs/architecture/overview.md) for the
full security architecture.
