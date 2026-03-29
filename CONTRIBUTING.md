# Contributing

## Code of conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold it.

## Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

Scopes: `feat:`, `fix:`, `docs:`, `schema:`, `policy:`, `deploy:`, `test:`,
`chore:`

Examples:

- `schema: add bitemporal columns to threat_actor`
- `policy: restrict external_auditor to TLP:GREEN`
- `fix: parameterise Cypher query in entity_resolve`

## Pull requests

- One concern per PR
- Smallest safe increment
- Schema changes require a new numbered migration file
- Policy changes require corresponding test updates in `tests/auth/`
- RLS changes require corresponding test updates in `tests/rls/`

## Code style

- Python: ruff, type hints required, Python 3.12+
- SQL: lowercase keywords, 4-space indent
- YAML: 2-space indent
- Markdown: no trailing whitespace (except line breaks)

## Security

Never commit secrets. If you accidentally commit a secret, notify the
maintainer immediately. See [SECURITY.md](SECURITY.md).
